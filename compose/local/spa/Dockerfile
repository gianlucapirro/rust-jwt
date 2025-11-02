FROM oven/bun:latest

# Create app directory
WORKDIR /app

# Install dependencies first
COPY package.json bun.lock ./
RUN bun i

# Copy everything (only for initial build)
COPY . .

# Expose Vite/React Router dev port
EXPOSE 5000

CMD ["bun", "run", "dev", "--", "--host", "0.0.0.0", "--port", "5000"]
