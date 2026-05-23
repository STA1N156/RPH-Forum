# 🎭 角色卡广场 (RP Forum)

一个自部署的角色卡分享论坛，支持 Docker 一键部署到 Zeabur。

## ✨ 功能特性

- **角色卡上传与分享** - 支持 PNG/JSON 格式的角色卡文件
- **匿名评论系统** - 所有人都可以匿名评论
- **下载积分系统** - 上传赚积分，下载消耗积分
- **管理员后台** - 专业的 Web 管理界面
- **暴力破解防护** - IP/账户级别登录限制
- **内置 SQLite 数据库** - 无需外部数据库服务
- **Docker 部署** - 一个容器包含所有服务
- **数据持久化** - 通过 Volume 挂载保存数据

## 🚀 一键部署到 Zeabur

[![Deploy on Zeabur](https://zeabur.com/button.svg)](https://zeabur.com/templates?q=rp-forum)

### 部署步骤

1. Fork 本仓库到你的 GitHub 账户
2. 在 [Zeabur](https://zeabur.com) 注册/登录
3. 创建新项目 → 选择「从 GitHub 部署」→ 选择 fork 的仓库
4. 部署完成后，在服务设置中添加 **Volume 挂载**：
   - Volume ID: `data`
   - 挂载路径: `/app/data`
5. 首次登录后立即修改管理员密码
6. 访问 `https://你的域名/admin` 进入管理后台

## ⚙️ 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ADMIN_USERNAME` | `admin` | 管理员用户名 |
| `ADMIN_PASSWORD` | 平台生成强密码 | 管理员初始密码，生产环境必须显式设置 |
| `JWT_SECRET` | 平台生成强密钥 | JWT 签名密钥，建议显式设置；未设置时会回退为基于 ADMIN_PASSWORD 派生的稳定密钥 |
| `PORT` | `9191` | 服务端口 |
| `DATA_DIR` | `/app/data` | 数据存储目录 |

## 🔒 安全特性

- **登录速率限制**: 每个 IP + 用户名组合 15 分钟内最多 5 次尝试
- **JWT 认证**: 管理员接口需要令牌验证
- **密码哈希**: 使用 bcrypt (cost=12) 存储密码
- **安全头**: 通过 Helmet 中间件设置安全响应头
- **审计日志**: 记录所有登录尝试（成功/失败）
- **健康检查**: 容器通过 `/health` 端点暴露存活状态

## 🖥️ 管理后台

访问 `/admin` 路径进入管理后台，功能包括：

- **仪表盘** - 卡片/评论/下载统计总览
- **卡片管理** - 搜索、分页、删除卡片
- **评论管理** - 查看、删除评论
- **用户管理** - 调整下载次数、重置用户密码
- **标签管理** - 编辑热门标签、标签库与隐藏标签
- **操作日志** - 查看登录尝试和管理员操作记录
- **系统设置** - 站点名称、权限配置、修改密码

## 🐳 本地开发

```bash
# 安装依赖
npm install

# 启动服务
npm start

# 访问
# 论坛: http://localhost:9191
# 管理后台: http://localhost:9191/admin
```

### Docker 本地运行

```bash
docker build -t rp-forum .
docker run -p 9191:9191 -v rp-forum-data:/app/data rp-forum
```

## 📁 项目结构

```
├── server.js          # Express 服务器 (API + 静态文件)
├── database.js        # SQLite 数据库初始化
├── package.json       # 依赖配置
├── Dockerfile         # Docker 构建文件
├── zeabur.json        # Zeabur 部署模板
├── public/
│   ├── index.html     # 论坛主页 (Vue.js + Tailwind)
│   └── admin.html     # 管理后台
└── data/              # SQLite 数据库 (运行时生成)
```

## 📜 License

MIT
