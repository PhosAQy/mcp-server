#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { OAuthManager } from "./auth/OAuthManager.js";
import { DemoxClient, AuthError } from "./api/DemoxClient.js";
import { logger } from "./utils/config.js";

/**
 * Demox MCP Server
 *
 * 提供 Demox 平台的 MCP 接口，支持：
 * - 部署静态网站
 * - 查看网站列表
 * - 删除网站
 * - 管理网站
 */
class DemoxMCPServer {
  private server: Server;
  private oauthManager: OAuthManager;
  private demoxClient: DemoxClient | null = null;

  constructor() {
    logger.info("正在初始化 Demox MCP Server...");

    this.server = new Server(
      {
        name: "@demox/mcp-server",
        version: "1.1.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.oauthManager = new OAuthManager();

    this.setupHandlers();
  }

  /**
   * 设置请求处理器
   */
  private setupHandlers(): void {
    // 工具列表
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return {
        tools: [
          {
            name: "deploy_website",
            description:
              "部署静态网站到 Demox 平台。支持目录、ZIP、PDF 和文档；PDF/文档会先转换为静态站点再部署。",
            inputSchema: {
              type: "object",
              properties: {
                zipFile: {
                  type: "string",
                  description:
                    "文件或目录路径。支持：1) 本地目录（自动打包）2) 本地 ZIP 3) PDF 4) .md/.markdown/.txt/.docx 文档 5) HTTPS ZIP URL。**不支持 base64 内容**。",
                },
                websiteId: {
                  type: "string",
                  description:
                    "网站 ID（可选）。如果不提供，将创建新网站；如果提供，将更新现有网站",
                },
                projectId: {
                  type: "string",
                  description: "项目 ID（可选）。不提供时部署到当前用户的 default 项目",
                },
                fileName: {
                  type: "string",
                  description: "网站名称，用于标识和展示。如果不提供，会自动使用目录或文件名",
                },
                templateId: {
                  type: "string",
                  enum: ["insight", "warm", "dark"],
                  description:
                    "文档转网页时使用的模板，可选 insight、warm、dark。仅对文档文件生效，默认 insight",
                },
              },
              required: ["zipFile"],
            },
          },
          {
            name: "list_websites",
            description:
              "获取用户在 Demox 平台上的所有网站列表，包括网站 ID、名称、URL 和创建时间",
            inputSchema: {
              type: "object",
              properties: {},
            },
          },
          {
            name: "list_projects",
            description:
              "获取用户在 Demox 平台上的所有项目列表，包括项目 ID、名称、slug 和站点数量",
            inputSchema: {
              type: "object",
              properties: {},
            },
          },
          {
            name: "get_website",
            description:
              "获取指定网站的详细信息，包括文件列表、部署历史等",
            inputSchema: {
              type: "object",
              properties: {
                websiteId: {
                  type: "string",
                  description: "要查询的网站 ID",
                },
              },
              required: ["websiteId"],
            },
          },
          {
            name: "check_custom_domain",
            description:
              "检查官方域名子域名前缀是否可用，域名格式为 <subdomain>.<domain>",
            inputSchema: {
              type: "object",
              properties: {
                subdomain: {
                  type: "string",
                  minLength: 5,
                  maxLength: 63,
                  description: "要检查的子域名前缀，5-63 位，例如 my-demo",
                },
                websiteId: {
                  type: "string",
                  description:
                    "当前网站 ID（可选）。传入后，如果该前缀已绑定到自己，也会视为可用",
                },
                domain: {
                  type: "string",
                  enum: ["demox.site", "vibeme.cn"],
                  description: "官方域名后缀，默认 demox.site",
                },
              },
              required: ["subdomain"],
            },
          },
          {
            name: "set_custom_domain",
            description:
              "为指定网站设置自定义子域名前缀。设置后优先展示自定义域名。",
            inputSchema: {
              type: "object",
              properties: {
                websiteId: {
                  type: "string",
                  description: "要设置自定义域名的网站 ID",
                },
                subdomain: {
                  type: "string",
                  minLength: 5,
                  maxLength: 63,
                  description: "子域名前缀，5-63 位，例如 my-demo",
                },
                domain: {
                  type: "string",
                  enum: ["demox.site", "vibeme.cn"],
                  description: "官方域名后缀，默认 demox.site",
                },
              },
              required: ["websiteId", "subdomain"],
            },
          },
          {
            name: "clear_custom_domain",
            description:
              "清除指定网站的自定义子域名前缀，网站仍可通过默认域名访问。",
            inputSchema: {
              type: "object",
              properties: {
                websiteId: {
                  type: "string",
                  description: "要清除自定义域名的网站 ID",
                },
              },
              required: ["websiteId"],
            },
          },
          {
            name: "delete_website",
            description:
              "删除指定的网站及其所有文件。此操作不可撤销，请谨慎使用。",
            inputSchema: {
              type: "object",
              properties: {
                websiteId: {
                  type: "string",
                  description: "要删除的网站 ID",
                },
              },
              required: ["websiteId"],
            },
          },
        ],
      };
    });

    // 工具调用
    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        // 确保已认证
        let accessToken = await this.oauthManager.ensureAuthenticated();

        // 延迟初始化客户端（需要 Token）
        if (!this.demoxClient) {
          this.demoxClient = new DemoxClient(accessToken);
        }

        // 路由到具体的处理方法
        switch (name) {
          case "deploy_website":
            return await this.handleDeploy(args, accessToken);
          case "list_websites":
            return await this.handleList(accessToken);
          case "list_projects":
            return await this.handleListProjects(accessToken);
          case "get_website":
            return await this.handleGet(args, accessToken);
          case "check_custom_domain":
            return await this.handleCheckCustomDomain(args, accessToken);
          case "set_custom_domain":
            return await this.handleSetCustomDomain(args, accessToken);
          case "clear_custom_domain":
            return await this.handleClearCustomDomain(args, accessToken);
          case "delete_website":
            return await this.handleDelete(args, accessToken);
          default:
            throw new Error(`未知工具: ${name}`);
        }
      } catch (error: any) {
        logger.error(`工具调用失败 (${name}):`, error.message);

        // 检查是否是 AuthError 实例或包含认证相关的错误信息
        const isAuthError = error.name === "AuthError" ||
                            error.message.includes("Token") ||
                            error.message.includes("认证") ||
                            error.message.includes("登录") ||
                            error.message.includes("UNAUTHORIZED") ||
                            error.message.includes("401");

        if (isAuthError) {
          logger.info("检测到认证错误，自动触发登录流程...");

          try {
            // 自动触发登录
            const newAccessToken = await this.oauthManager.authorize();

            // 重新初始化客户端
            this.demoxClient = new DemoxClient(newAccessToken);

            logger.info("登录成功，正在重试工具调用...");

            // 重新执行工具调用
            switch (name) {
              case "deploy_website":
                return await this.handleDeploy(args, newAccessToken);
              case "list_websites":
                return await this.handleList(newAccessToken);
              case "list_projects":
                return await this.handleListProjects(newAccessToken);
              case "get_website":
                return await this.handleGet(args, newAccessToken);
              case "check_custom_domain":
                return await this.handleCheckCustomDomain(args, newAccessToken);
              case "set_custom_domain":
                return await this.handleSetCustomDomain(args, newAccessToken);
              case "clear_custom_domain":
                return await this.handleClearCustomDomain(args, newAccessToken);
              case "delete_website":
                return await this.handleDelete(args, newAccessToken);
              default:
                throw new Error(`未知工具: ${name}`);
            }
          } catch (loginError: any) {
            logger.error("自动登录失败:", loginError.message);
            return {
              content: [
                {
                  type: "text",
                  text: `❌ **自动登录失败**

错误信息: ${loginError.message}

请尝试手动运行以下命令完成登录：

\`\`\`bash
demox-mcp login
\`\`\`

登录完成后，请重新调用此工具。`,
                },
              ],
              isError: true,
            };
          }
        }

        return {
          content: [
            {
              type: "text",
              text: `❌ 错误: ${error.message}`,
            },
          ],
          isError: true,
        };
      }
    });
  }

  /**
   * 处理网站部署
   */
  private async handleDeploy(args: any, accessToken: string) {
    const { zipFile, websiteId, projectId, fileName: providedFileName, templateId } = args;

    // 参数验证
    if (!zipFile) {
      throw new Error("缺少必需参数: zipFile");
    }

    // 如果没有提供 fileName，尝试从路径推断
    let fileName = providedFileName;
    if (!fileName) {
      if (zipFile.includes("/") || zipFile.includes("\\")) {
        // 是路径：提取目录名或文件名
        const parts = zipFile.split(/\/|\\/);
        const lastPart = parts[parts.length - 1];
        fileName = lastPart.replace(".zip", "") || "unnamed";
      } else {
        fileName = "unnamed";
      }
    }

    logger.info(`开始部署网站: ${fileName}`);

    try {
      const result = await this.demoxClient!.deployWebsite(
        {
          zipFile,
          websiteId,
          projectId,
          fileName,
          templateId,
        },
        accessToken
      );

      return {
        content: [
          {
            type: "text",
            text: `✅ 网站部署成功！

**网站名称**: ${fileName}
**网站 ID**: ${result.websiteId}
${result.projectId ? `**项目 ID**: ${result.projectId}\n` : ""}**访问地址**: ${result.url}
${result.customUrl && result.defaultUrl && result.customUrl !== result.defaultUrl ? `**默认域名**: ${result.defaultUrl}\n` : ""}**部署路径**: ${result.path}

您现在可以访问上述地址查看您的网站了。`,
          },
        ],
      };
    } catch (error: any) {
      logger.error("部署失败:", error);
      // 确保错误被正确传播，不会导致进程崩溃
      throw error;
    }
  }

  /**
   * 处理网站列表
   */
  private async handleList(accessToken: string) {
    logger.info("获取网站列表");

    const websites = await this.demoxClient!.listWebsites(accessToken);

    if (websites.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "您还没有部署任何网站。\n\n使用 deploy_website 工具来创建您的第一个网站吧！",
          },
        ],
      };
    }

    // 格式化网站列表
    const listText = websites
      .map((site, index) => {
        const date = new Date(site.createdAt).toLocaleString("zh-CN");
        return `${index + 1}. **${site.fileName}**
   - ID: \`${site.websiteId}\`
${site.projectName || site.projectId ? `   - 项目: ${site.projectName || site.projectId}\n` : ""}   - URL: ${site.url}
${site.customUrl && site.defaultUrl && site.customUrl !== site.defaultUrl ? `   - 默认域名: ${site.defaultUrl}\n` : ""}   - 创建时间: ${date}
`;
      })
      .join("\n");

    return {
      content: [
        {
          type: "text",
          text: `📋 您的网站列表（共 ${websites.length} 个）

${listText}`,
        },
      ],
    };
  }

  /**
   * 处理项目列表
   */
  private async handleListProjects(accessToken: string) {
    logger.info("获取项目列表");

    const projects = await this.demoxClient!.listProjects(accessToken);

    if (projects.length === 0) {
      return {
        content: [
          {
            type: "text",
            text: "您还没有项目。部署新网站时会自动创建 default 项目。",
          },
        ],
      };
    }

    const listText = projects
      .map((project, index) => {
        return `${index + 1}. **${project.name}**
   - ID: \`${project.id}\`
   - Slug: ${project.slug}
   - 站点数: ${project.websitesCount || 0}
`;
      })
      .join("\n");

    return {
      content: [
        {
          type: "text",
          text: `📁 您的项目列表（共 ${projects.length} 个）\n\n${listText}`,
        },
      ],
    };
  }

  /**
   * 处理获取网站详情
   */
  private async handleGet(args: any, accessToken: string) {
    const { websiteId } = args;

    if (!websiteId) {
      throw new Error("缺少必需参数: websiteId");
    }

    logger.info(`获取网站详情: ${websiteId}`);

    const website = await this.demoxClient!.getWebsite(
      websiteId,
      accessToken
    );

    if (!website) {
      return {
        content: [
          {
            type: "text",
            text: `未找到网站: ${websiteId}`,
          },
        ],
      };
    }

    const createdDate = new Date(website.createdAt).toLocaleString("zh-CN");
    const updatedDate = new Date(website.updatedAt).toLocaleString("zh-CN");

    return {
      content: [
        {
          type: "text",
          text: `**网站详情**

**名称**: ${website.fileName}
**ID**: \`${website.websiteId}\`
${website.projectName || website.projectId ? `**项目**: ${website.projectName || website.projectId}\n` : ""}**URL**: ${website.url}
${website.customUrl && website.defaultUrl && website.customUrl !== website.defaultUrl ? `**默认域名**: ${website.defaultUrl}\n` : ""}**路径**: ${website.path}
**创建时间**: ${createdDate}
**更新时间**: ${updatedDate}`,
        },
      ],
    };
  }

  /**
   * 处理自定义域名可用性检查
   */
  private async handleCheckCustomDomain(args: any, accessToken: string) {
    const { subdomain, websiteId, domain = "demox.site" } = args;

    if (!subdomain) {
      throw new Error("缺少必需参数: subdomain");
    }

    const result = await this.demoxClient!.checkSubdomain(
      subdomain,
      accessToken,
      websiteId,
      domain
    );
    const host = `${subdomain}.${result.domain || domain}`;

    return {
      content: [
        {
          type: "text",
          text: result.available
            ? `✅ **${host}** 可用`
            : `⚠️ **${host}** 不可用\n\n原因: ${result.message || result.reason || "未知"}`,
        },
      ],
    };
  }

  /**
   * 处理设置自定义域名
   */
  private async handleSetCustomDomain(args: any, accessToken: string) {
    const { websiteId, subdomain, domain = "demox.site" } = args;

    if (!websiteId) {
      throw new Error("缺少必需参数: websiteId");
    }
    if (!subdomain) {
      throw new Error("缺少必需参数: subdomain");
    }

    const result = await this.demoxClient!.setSubdomain(
      websiteId,
      subdomain,
      accessToken,
      domain
    );

    if (!result.success) {
      throw new Error(result.message || "设置自定义域名失败");
    }

    return {
      content: [
        {
          type: "text",
          text: `✅ 自定义域名已设置

**网站 ID**: \`${websiteId}\`
**访问地址**: ${result.url || `https://${subdomain}.${result.subdomainDomain || result.subdomain_domain || domain}/`}
${result.message ? `**提示**: ${result.message}` : ""}`,
        },
      ],
    };
  }

  /**
   * 处理清除自定义域名
   */
  private async handleClearCustomDomain(args: any, accessToken: string) {
    const { websiteId } = args;

    if (!websiteId) {
      throw new Error("缺少必需参数: websiteId");
    }

    const result = await this.demoxClient!.clearSubdomain(
      websiteId,
      accessToken
    );

    if (!result.success) {
      throw new Error(result.message || "清除自定义域名失败");
    }

    return {
      content: [
        {
          type: "text",
          text: `✅ 自定义域名已清除

**网站 ID**: \`${websiteId}\`
${result.message ? `**提示**: ${result.message}` : ""}`,
        },
      ],
    };
  }

  /**
   * 处理删除网站
   */
  private async handleDelete(args: any, accessToken: string) {
    const { websiteId } = args;

    if (!websiteId) {
      throw new Error("缺少必需参数: websiteId");
    }

    logger.info(`删除网站: ${websiteId}`);

    await this.demoxClient!.deleteWebsite(websiteId, accessToken);

    return {
      content: [
        {
          type: "text",
          text: `✅ 网站已删除

**网站 ID**: ${websiteId}

⚠️ 注意：此操作不可撤销，网站的所有文件已被永久删除。`,
        },
      ],
    };
  }

  /**
   * 启动服务器
   */
  async start(): Promise<void> {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);

    logger.info("✅ Demox MCP Server 已启动");
    logger.info("等待工具调用...");
  }
}

// 启动服务器
const server = new DemoxMCPServer();
server.start().catch((error) => {
  logger.error("服务器启动失败:", error);
  process.exit(1);
});
