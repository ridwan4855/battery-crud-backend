const { spawn } = require("child_process");
const path = require("path");

module.exports = (req, res) => {
  const goBinaryPath = path.resolve(__dirname, "../go-api");

  const go = spawn(goBinaryPath);

  go.stdout.on("data", (data) => res.write(data));
  go.stderr.on("data", (data) => console.error(`stderr: ${data}`));
  go.on("close", () => res.end());
};
