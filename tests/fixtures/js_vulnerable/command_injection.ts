import { exec, execSync, spawn } from 'child_process';

export function pingHost(host: string): void {
  // Finding 1: string concatenation in exec()
  exec('ping -c 4 ' + host, (err, stdout) => {
    console.log(stdout);
  });
}

export function inspectDirectory(userPath: string): string {
  // Finding 2: template string with variable interpolation in execSync()
  return execSync(`ls -la ${userPath}`).toString();
}

export function runShellScript(scriptPath: string): void {
  // Finding 3: spawn with shell: true and dynamic command string
  spawn(`sh ${scriptPath}`, { shell: true });
}
