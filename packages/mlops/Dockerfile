FROM node:22-bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
    && rm -rf /var/lib/apt/lists/*

RUN corepack enable && corepack prepare pnpm@11.6.0 --activate

WORKDIR /app

COPY . .

# The collector never imports @logsguardian/core, so it never touches onnxruntime-node
# at runtime. Its postinstall otherwise downloads the full CUDA runtime (~600MB), which
# OOM-kills small instances for no benefit here.
ENV ONNXRUNTIME_NODE_INSTALL=skip

RUN pnpm install --frozen-lockfile
RUN pnpm -r run build

EXPOSE 4790

CMD ["node", "packages/mlops/dist/collector/bin.js"]
