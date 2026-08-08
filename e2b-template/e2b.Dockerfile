# Assay's eval sandbox template: the E2B default image, plus a Node
# current enough to install what artifacts actually declare.
#
# The vendor default ships Node 20.9.0; the modern toolchain floor is
# 20.19 (vite 8's engines field, among others), and 162 installs in one
# production catalog sweep terminal-failed on exactly that gap.
#
# Build & publish (needs `npm i -g @e2b/cli` and `e2b auth login`):
#
#   cd e2b-template
#   e2b template build --name assay-node22
#
# then point the worker at it:
#
#   E2B_TEMPLATE=assay-node22
FROM e2bdev/code-interpreter:latest

# Node 22 for the modern-toolchain floor, plus Python + pip and build
# tools so ecosystem-aware installs (pip for Python MCP servers, native
# addon builds) have what they need.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
  && apt-get update \
  && apt-get install -y nodejs python3 python3-pip python3-venv build-essential \
  && node --version \
  && npm --version \
  && python3 --version \
  && python3 -m pip --version
