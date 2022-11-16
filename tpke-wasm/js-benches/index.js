import init from "./pkg/tpke_wasm.js";
import { Setup } from "./pkg/tpke_wasm.js";

const runBenchmarks = async () => {
    console.log("Initializing ...");

    const setup = new Setup();

    console.log("Setup: ", setup);

    console.log("Done!");
};

init()
    .then(runBenchmarks)
    .catch((err) => console.error(err));