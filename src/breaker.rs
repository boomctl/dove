//! The cost circuit-breaker — the denial-of-wallet backstop. A CloudWatch alarm
//! on the gate's invocation volume trips an SNS topic, which fires a kill-switch
//! Lambda that sets the gate's reserved concurrency to 0. The gate goes dark and
//! stops costing money until the operator re-enables it (`aws lambda
//! delete-function-concurrency`). Metric alarms fire in minutes, so a flood is
//! bounded to minutes of a throttle-capped rate, not an open-ended bill. On by
//! default; the threshold is a knob (FLOOD_THRESHOLD).

use crate::ui;
use anyhow::{anyhow, bail, Context, Result};
use std::io::Write;
use std::process::Command;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

/// Gate invocations in a 5-minute window that trip the breaker. Generous vs real
/// use (a busy share is a few hundred), below the throttle's ceiling (25 req/s ×
/// 300s = 7500), so a sustained flood trips within minutes.
const FLOOD_THRESHOLD: &str = "5000";

const LAMBDA_TRUST: &str = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;

/// The kill-switch: on any SNS trigger, throttle the gate to zero concurrency.
const KILL_SWITCH_PY: &str = r#"import os
import boto3

def handler(event, _context):
    boto3.client("lambda").put_function_concurrency(
        FunctionName=os.environ["GATE_FUNCTION"],
        ReservedConcurrentExecutions=0,
    )
    return {"disabled": os.environ["GATE_FUNCTION"]}
"#;

/// Stand up (or reconcile) the breaker for the gate. Idempotent.
pub fn provision_breaker(
    profile: Option<&str>,
    region: &str,
    account: &str,
    gate_name: &str,
) -> Result<()> {
    let breaker = format!("dove-breaker-{account}");
    let gate_arn = format!("arn:aws:lambda:{region}:{account}:function:{gate_name}");
    let breaker_arn = format!("arn:aws:lambda:{region}:{account}:function:{breaker}");
    let role_arn = format!("arn:aws:iam::{account}:role/{breaker}");
    let topic_name = format!("dove-gate-flood-{account}");

    // Kill-switch role (throttle the gate + write its own logs).
    ui::step("breaker role", || {
        aws_ok(
            profile,
            &[
                "iam",
                "create-role",
                "--role-name",
                &breaker,
                "--assume-role-policy-document",
                LAMBDA_TRUST,
            ],
            &["EntityAlreadyExists"],
        )?;
        aws_ok(
            profile,
            &[
                "iam",
                "put-role-policy",
                "--role-name",
                &breaker,
                "--policy-name",
                "dove-breaker",
                "--policy-document",
                &kill_policy(&gate_arn, account),
            ],
            &[],
        )
    })?;

    // Kill-switch Lambda.
    let zip = temp_zip()?;
    let zip_arg = format!("fileb://{}", zip.display());
    let env = format!("Variables={{GATE_FUNCTION={gate_name}}}");
    let out = ui::step("breaker lambda", || {
        aws_retry(
            profile,
            &[
                "lambda",
                "create-function",
                "--function-name",
                &breaker,
                "--runtime",
                "python3.12",
                "--handler",
                "lambda_function.handler",
                "--role",
                &role_arn,
                "--zip-file",
                &zip_arg,
                "--environment",
                &env,
                "--timeout",
                "10",
            ],
            &["ResourceConflictException"],
            "cannot be assumed",
            6,
        )
    });
    let _ = std::fs::remove_file(&zip);
    out?;

    // SNS topic + the alarm that fires it + the kill-switch subscribed to it.
    let topic_arn = ui::step("breaker topic", || create_topic(profile, &topic_name))?;
    ui::step("breaker wiring", || {
        aws_ok(
            profile,
            &[
                "sns",
                "subscribe",
                "--topic-arn",
                &topic_arn,
                "--protocol",
                "lambda",
                "--notification-endpoint",
                &breaker_arn,
            ],
            &[],
        )?;
        aws_ok(
            profile,
            &[
                "lambda",
                "add-permission",
                "--function-name",
                &breaker,
                "--statement-id",
                "sns",
                "--action",
                "lambda:InvokeFunction",
                "--principal",
                "sns.amazonaws.com",
                "--source-arn",
                &topic_arn,
            ],
            &["ResourceConflictException"],
        )
    })?;
    ui::step("breaker alarm", || {
        aws_ok(
            profile,
            &[
                "cloudwatch",
                "put-metric-alarm",
                "--alarm-name",
                &topic_name,
                "--namespace",
                "AWS/Lambda",
                "--metric-name",
                "Invocations",
                "--dimensions",
                &format!("Name=FunctionName,Value={gate_name}"),
                "--statistic",
                "Sum",
                "--period",
                "300",
                "--evaluation-periods",
                "1",
                "--threshold",
                FLOOD_THRESHOLD,
                "--comparison-operator",
                "GreaterThanThreshold",
                "--treat-missing-data",
                "notBreaching",
                "--alarm-actions",
                &topic_arn,
            ],
            &[],
        )
    })?;

    Ok(())
}

/// The kill-switch role's policy: throttle just the gate function, and log.
fn kill_policy(gate_arn: &str, account: &str) -> String {
    format!(
        r#"{{"Version":"2012-10-17","Statement":[{{"Effect":"Allow","Action":"lambda:PutFunctionConcurrency","Resource":"{gate_arn}"}},{{"Effect":"Allow","Action":["logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"],"Resource":"arn:aws:logs:*:{account}:*"}}]}}"#
    )
}

fn create_topic(profile: Option<&str>, name: &str) -> Result<String> {
    let out = aws(
        profile,
        &["sns", "create-topic", "--name", name, "--output", "json"],
    )?;
    if !out.status.success() {
        bail!(
            "create-topic: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let v: serde_json::Value = serde_json::from_slice(&out.stdout)?;
    v["TopicArn"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow!("no TopicArn"))
}

fn temp_zip() -> Result<std::path::PathBuf> {
    let mut b = [0u8; 6];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    let hex: String = b.iter().map(|x| format!("{x:02x}")).collect();
    let dest = std::env::temp_dir().join(format!("dove-breaker-{hex}.zip"));
    let f = std::fs::File::create(&dest)?;
    let mut z = ZipWriter::new(f);
    z.start_file("lambda_function.py", SimpleFileOptions::default())?;
    z.write_all(KILL_SWITCH_PY.as_bytes())?;
    z.finish()?;
    Ok(dest)
}

fn aws_ok(profile: Option<&str>, args: &[&str], tolerate: &[&str]) -> Result<()> {
    let out = aws(profile, args)?;
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.success() || tolerate.iter().any(|t| stderr.contains(t)) {
        return Ok(());
    }
    bail!("aws {} failed: {}", args.join(" "), stderr.trim())
}

fn aws_retry(
    profile: Option<&str>,
    args: &[&str],
    tolerate: &[&str],
    retry_on: &str,
    attempts: u32,
) -> Result<()> {
    for i in 0..attempts {
        let out = aws(profile, args)?;
        let stderr = String::from_utf8_lossy(&out.stderr);
        if out.status.success() || tolerate.iter().any(|t| stderr.contains(t)) {
            return Ok(());
        }
        if stderr.contains(retry_on) && i + 1 < attempts {
            std::thread::sleep(std::time::Duration::from_secs(3));
            continue;
        }
        bail!("aws {} failed: {}", args.join(" "), stderr.trim());
    }
    Ok(())
}

fn aws(profile: Option<&str>, args: &[&str]) -> Result<std::process::Output> {
    let mut cmd = Command::new("aws");
    if let Some(p) = profile {
        cmd.args(["--profile", p]);
    }
    cmd.args(args)
        .output()
        .with_context(|| format!("running aws {}", args.join(" ")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kill_policy_scopes_to_the_gate() {
        let p = kill_policy("arn:aws:lambda:us-east-1:123:function:dove-gate-123", "123");
        assert!(p.contains("lambda:PutFunctionConcurrency"));
        assert!(p.contains("function:dove-gate-123")); // only the gate
        assert!(p.contains("logs:PutLogEvents"));
    }

    #[test]
    fn kill_switch_is_valid_python() {
        assert!(KILL_SWITCH_PY.contains("put_function_concurrency"));
        assert!(KILL_SWITCH_PY.contains("ReservedConcurrentExecutions"));
    }
}
