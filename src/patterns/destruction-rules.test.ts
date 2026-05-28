import { describe, expect, it } from "vitest";
import { scanDestruction } from "./destruction-rules.js";

describe("scanDestruction", () => {
  it("blocks rm -rf against filesystem-root / system / home paths", () => {
    expect(scanDestruction("rm -rf /")).not.toBeNull();
    expect(scanDestruction("rm -rf /etc")).not.toBeNull();
    expect(scanDestruction("rm -rf $HOME")).not.toBeNull();
    expect(scanDestruction("rm -rf ~/")).not.toBeNull();
    expect(scanDestruction("rm -rf /Users/oleg")).not.toBeNull();
  });

  it("does not flag rm against project paths", () => {
    expect(scanDestruction("rm -rf ./dist")).toBeNull();
    expect(scanDestruction("rm -rf node_modules")).toBeNull();
  });

  it("does not flag non-recursive rm", () => {
    // rm -f / can't delete a directory; treating it as destruction would FP.
    expect(scanDestruction("rm -f /etc/foo")).toBeNull();
  });

  it("blocks dd to block devices", () => {
    expect(scanDestruction("dd if=/dev/zero of=/dev/sda bs=1M")).not.toBeNull();
    expect(scanDestruction("dd if=img of=/dev/nvme0")).not.toBeNull();
  });

  it("blocks mkfs on block devices", () => {
    expect(scanDestruction("mkfs.ext4 /dev/sda1")).not.toBeNull();
  });

  it("blocks git force-push to protected branches", () => {
    expect(scanDestruction("git push --force origin main")).not.toBeNull();
    expect(scanDestruction("git push origin master --force")).not.toBeNull();
    expect(scanDestruction("git push --force-with-lease origin production")).not.toBeNull();
  });

  it("does not flag force-push to feature branches", () => {
    expect(scanDestruction("git push --force origin feature/foo")).toBeNull();
  });

  it("blocks terraform destroy without --target", () => {
    expect(scanDestruction("terraform destroy -auto-approve")).not.toBeNull();
    expect(scanDestruction("tofu destroy")).not.toBeNull();
  });

  it("allows terraform destroy with --target", () => {
    expect(scanDestruction("terraform destroy --target=aws_s3_bucket.x")).toBeNull();
  });

  it("blocks kubectl delete namespace and delete --all", () => {
    expect(scanDestruction("kubectl delete ns production")).not.toBeNull();
    expect(scanDestruction("kubectl delete pods --all")).not.toBeNull();
  });

  it("allows kubectl delete --all with a selector", () => {
    expect(scanDestruction("kubectl delete pods --all --selector=app=foo")).toBeNull();
    expect(scanDestruction("kubectl delete pods --all -l app=foo")).toBeNull();
  });

  it("blocks DROP DATABASE", () => {
    expect(scanDestruction("DROP DATABASE prod")).not.toBeNull();
    expect(scanDestruction("drop database staging;")).not.toBeNull();
  });

  it("returns null on safe commands", () => {
    expect(scanDestruction("ls -la")).toBeNull();
    expect(scanDestruction("git status")).toBeNull();
    expect(scanDestruction("echo hello world")).toBeNull();
    expect(scanDestruction("")).toBeNull();
  });

  it("scans each segment of a compound shell command", () => {
    // The safe lead-up shouldn't shield the dangerous tail.
    expect(scanDestruction("ls; rm -rf /")).not.toBeNull();
    expect(scanDestruction("ls && rm -rf /")).not.toBeNull();
  });
});
