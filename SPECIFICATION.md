# headless-xi-client

Our goal is to write a headless Rust package and CLI tool that can be used to query the map and/or cache server of a Final Fantasy XI instance. We're targeting private servers specifically running on LandSandBoat, but it could work for retail as well.

I would like us to use Rust. A minimal implementation of an existing client can be found in https://github.com/claywar/HeadlessXI/tree/main/headlessxi. However, it is 5 years old so you should treat it with caution.
You should check https://github.com/LandSandBoat/server if there are any problems to figure out any changes that have happened. You may need to clone these repos to investigate.

The initial version should focus on being able to list the characters online. This is known as "/sea all" for Final Fantasy XI. https://github.com/atom0s/XiPackets has documentation on packets if needed.

## Architecture

Make sure to seperate out the CLI from the create logic that will allow parsing packets and a stream. We should be able to build them independently.

## Testing

We will need a live server to test against. As far as I can tell, one such server is found at `66.85.159.114:54002` and it is known as "Horizon XI". You can should try to connect to this one. Unit tests should be done until we're sure things work. We should only connect to a live instance once we're sure things work.

Let's make running the CLI the way to test against this. Make a shell script for Horizon specifically.
