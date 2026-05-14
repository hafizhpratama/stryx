// The exported helper uses `execFile` with a hardcoded binary path
// and the user input passed as an argv element. `execFile` does not
// invoke a shell, so metacharacters in the argv array are passed
// verbatim — no command injection. The rule checks only the first
// argument (binary path); the array is the second arg and doesn't
// trigger.

import { execFile } from "child_process";

export async function convertVideo(input: string) {
  execFile("ffmpeg", ["-i", input, "out.mp4"]);
}
