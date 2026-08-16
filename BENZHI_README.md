# BENZHI_README

## 项目说明
- 项目：benzhi-project-5eefd8e2-7fc8-407b-a737-0072e7aefec3
- 项目用途：Repaired incident lifecycle/navigation, cursor-safe live updates with polling refresh, incident-timezone browser handling, durable natural expiry reconciliation, and retryable failed relay attempts. Build, focused workflow, full tests, vet, and CLI smoke pass. The startup probe was run, but the managed sandbox denied TCP socket creation with "operation not permitted"; the command remains valid for a socket-capable environment.
- Go 工具链：`golang:1.26.0`
- 前端工具链：无

## 标准构建、运行和测试命令
进入容器后执行：
cd '/app' && GOTOOLCHAIN=local go build ./...
cd /app && GOTOOLCHAIN=local go run ./cmd/netweave --help
cd '/app' && GOTOOLCHAIN=local go test ./...

## Docker 构建和进入容器
chmod +x build_benzhi_docker.sh
./build_benzhi_docker.sh benzhi-project-5eefd8e2-7fc8-407b-a737-0072e7aefec3-amd64 linux/amd64
./build_benzhi_docker.sh benzhi-project-5eefd8e2-7fc8-407b-a737-0072e7aefec3-arm64 linux/arm64
docker run -it benzhi-project-5eefd8e2-7fc8-407b-a737-0072e7aefec3-amd64:latest

## 题目验证命令
1. 预期退出码 0：`go test ./...`
2. 预期退出码 0：`go vet ./...`
3. 预期退出码 0：`go build ./...`
4. 预期退出码 0：`go test ./internal/httpapp -run TestOperatorWorkflow -count=1`
5. 预期退出码 0：`go run ./cmd/netweave --help`
