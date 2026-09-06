import { exec, execFile, spawn } from 'child_process';

// Safe 1: static literal command
export function checkGitStatus(): void {
  exec('git status', (err, stdout) => {
    console.log(stdout);
  });
}

// Safe 2: spawn with argument array and no shell
export function listFilesSafe(targetDir: string): void {
  spawn('ls', ['-la', targetDir], { shell: false });
}

// Safe 3: execFile with argument array
export function runTestsSafe(): void {
  execFile('npm', ['test'], (err, stdout) => {
    console.log(stdout);
  });
}
