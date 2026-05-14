// The exported helper splices its parameter directly into the
// shell-interpreting `exec`. `convertVideo`'s parameter `input`
// flows into the command-string first-arg with no allow-list or
// argv-array switch.

import { exec } from "child_process";

export async function convertVideo(input: string) {
  exec(`ffmpeg -i ${input} out.mp4`);
}
