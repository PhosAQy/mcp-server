import { loadConfig, logger } from "../utils/config.js";
import {
  buildDocumentSiteZip,
  buildPdfSiteZip,
  isSupportedDocPath,
  isSupportedPdfPath,
} from "../utils/site-packager.js";

/**
 * 鉴权错误类
 * 当 token 过期或无效时抛出此错误，触发自动重新登录
 */
export class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthError";
  }
}

/**
 * 部署参数
 */
export interface DeployParams {
  zipFile: string;
  websiteId?: string;
  projectId?: string;
  fileName: string;
  templateId?: string;
}

/**
 * 部署结果
 */
export interface DeployResult {
  url: string;
  websiteId: string;
  projectId?: string | null;
  path: string;
  defaultUrl?: string;
  customUrl?: string | null;
  subdomainDomain?: string | null;
  preferredUrl?: string;
  cachePurge?: unknown;
}

/**
 * 网站信息
 */
export interface Website {
  websiteId: string;
  fileName: string;
  name?: string;
  url: string;
  path: string;
  subdomain?: string | null;
  subdomainDomain?: string | null;
  projectId?: string | null;
  projectName?: string | null;
  projectSlug?: string | null;
  defaultUrl?: string;
  customUrl?: string | null;
  preferredUrl?: string;
  createdAt: string;
  updatedAt: string;
}

export interface Project {
  id: string;
  name: string;
  slug: string;
  archived?: boolean;
  websitesCount?: number;
}

export interface DomainCheckResult {
  success: boolean;
  available: boolean;
  domain?: string;
  reason?: string;
  message?: string;
}

export interface DomainResult {
  success: boolean;
  subdomain?: string;
  subdomainDomain?: string;
  subdomain_domain?: string;
  url?: string;
  message?: string;
  code?: string;
}

/**
 * Demox API 客户端
 * 通过 SCF mcp-api 调用后端服务
 */
export class DemoxClient {
  private apiUrl: string;
  private websiteApiUrl: string;

  constructor(accessToken?: string) {
    const config = loadConfig();
    this.apiUrl = config.cloudFunctionUrl;
    this.websiteApiUrl = config.websiteApiUrl;
  }

  /**
   * 调用 API
   */
  private async callApi(
    path: string,
    data: Record<string, any>,
    accessToken: string,
    baseUrl = this.apiUrl
  ): Promise<any> {
    const https = await import("https");
    const urlModule = await import("url");

    try {
      logger.debug(`调用 API: ${path}`);
      logger.debug(`API URL: ${this.apiUrl}`);

      const urlObj = new urlModule.URL(baseUrl + path);
      const requestBodyStr = JSON.stringify(data);

      const responseData = await new Promise<any>((resolve, reject) => {
        const req = https.request(
          {
            hostname: urlObj.hostname,
            port: urlObj.port || 443,
            path: urlObj.pathname + urlObj.search,
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "Authorization": `Bearer ${accessToken}`,
              "Content-Length": Buffer.byteLength(requestBodyStr),
            },
          },
          (res: any) => {
            let body = "";
            res.on("data", (chunk: any) => {
              body += chunk;
            });
            res.on("end", () => {
              try {
                const jsonResponse = JSON.parse(body);
                resolve({
                  ok: res.statusCode && res.statusCode >= 200 && res.statusCode < 300,
                  status: res.statusCode,
                  data: jsonResponse,
                });
              } catch (e) {
                resolve({
                  ok: res.statusCode && res.statusCode >= 200 && res.statusCode < 300,
                  status: res.statusCode,
                  data: body,
                });
              }
            });
          }
        );

        req.on("error", (err: Error) => {
          reject(new Error(`请求失败: ${err.message}`));
        });

        req.write(requestBodyStr);
        req.end();
      });

      if (!responseData.ok) {
        const errorText = typeof responseData.data === "string"
          ? responseData.data
          : JSON.stringify(responseData.data);

        // 检查是否是鉴权错误
        if (responseData.status === 401 ||
            errorText.includes("UNAUTHORIZED") ||
            errorText.includes("TOKEN_INVALID") ||
            errorText.includes("AUTH_REQUIRED")) {
          logger.error("鉴权失败，需要重新登录");
          throw new AuthError("Token 已过期或无效，需要重新登录");
        }

        if (responseData.data && typeof responseData.data === "object" && responseData.data.message) {
          const code = responseData.data.code ? `[${responseData.data.code}] ` : "";
          throw new Error(`${code}${responseData.data.message}`);
        }

        throw new Error(`HTTP ${responseData.status}: ${errorText}`);
      }

      // 检查错误
      if (responseData.data && responseData.data.error) {
        const error = responseData.data.error;

        const authErrorCodes = [
          "TOKEN_INVALID",
          "AUTH_REQUIRED",
          "AUTH_ERROR",
          "UNAUTHORIZED",
          "TOKEN_EXPIRED",
          "NEED_LOGIN",
        ];

        if (authErrorCodes.includes(error.code)) {
          logger.error(`鉴权错误 [${error.code}]: ${error.message}`);
          throw new AuthError(error.message || "Token 已过期或无效");
        }

        throw new Error(
          `[${error.code}] ${error.message}${error.suggestion ? `\n建议：${error.suggestion}` : ""
          }`
        );
      }

      if (responseData.data && responseData.data.success === false) {
        throw new Error(responseData.data.message || "请求失败");
      }

      return responseData.data;
    } catch (error: any) {
      if (error instanceof AuthError) {
        throw error;
      }

      logger.error(`API调用失败 (${path}):`, error.message);
      throw error;
    }
  }

  /**
   * 部署网站
   */
  async deployWebsite(
    params: DeployParams,
    accessToken: string
  ): Promise<DeployResult> {
    // 如果没有提供 websiteId，生成一个新的
    let websiteId = params.websiteId;
    if (!websiteId) {
      websiteId = this.generateWebsiteId();
      logger.debug(`自动生成 websiteId: ${websiteId}`);
    }

    logger.info(`正在部署网站: ${params.fileName}`);

    // 处理输入路径（文件、目录或 URL），统一转换为本地 ZIP 文件
    let localFilePath: string | null = null;

    if (params.zipFile.startsWith("http://") || params.zipFile.startsWith("https://")) {
      // URL: 必须是 .zip 结尾
      if (!params.zipFile.toLowerCase().endsWith(".zip")) {
        throw new Error(`只支持 ZIP 文件，URL 必须以 .zip 结尾`);
      }

      logger.debug("检测到 ZIP URL，正在下载...");
      const buffer = await this.downloadZipFileToBuffer(params.zipFile);
      localFilePath = await this.saveBufferToTempFile(buffer);
    } else if (this.isBase64(params.zipFile) && !params.zipFile.startsWith("/") && !params.zipFile.startsWith(".")) {
      // Base64: 不再支持
      throw new Error(`不支持直接传入 Base64 内容，请提供 ZIP 文件路径或 URL`);
    } else {
      // 本地路径：文件或目录
      logger.debug(`检测到本地路径: ${params.zipFile}`);

      const stat = await this.getPathStat(params.zipFile);
      if (stat.isDirectory) {
        // 目录：打包成 ZIP
        const sourceProjectMessage = await this.detectSourceProjectDirectory(params.zipFile);
        if (sourceProjectMessage) {
          throw new Error(sourceProjectMessage);
        }
        logger.debug(`检测到目录: ${params.zipFile}，正在打包...`);
        localFilePath = await this.zipDirectoryToFile(params.zipFile);
      } else if (params.zipFile.toLowerCase().endsWith(".zip")) {
        // ZIP 文件：直接使用
        localFilePath = params.zipFile;
      } else if (isSupportedPdfPath(params.zipFile)) {
        logger.debug(`检测到 PDF: ${params.zipFile}，正在生成预览站点...`);
        const converted = await buildPdfSiteZip(params.zipFile);
        localFilePath = converted.zipFilePath;
        logger.info(`PDF 已转换为站点: ${converted.title}`);
      } else if (isSupportedDocPath(params.zipFile)) {
        logger.debug(`检测到文档: ${params.zipFile}，正在生成网页站点...`);
        const converted = await buildDocumentSiteZip(params.zipFile, params.templateId);
        localFilePath = converted.zipFilePath;
        logger.info(`文档已转换为站点: ${converted.title}`);
      } else {
        throw new Error(`不支持的文件类型，仅支持目录、.zip、.pdf、.md、.txt、.docx 文件`);
      }
    }

    if (!localFilePath) {
      throw new Error(`无法处理输入文件`);
    }

    // 显示文件大小并检查限制
    const fileSize = await this.getFileSize(localFilePath);
    logger.info(`文件大小: ${(fileSize / 1024 / 1024).toFixed(2)}MB`);

    // 检查文件大小限制（最大 8MB，因为 SCF 请求体限制）
    const maxFileSize = 8 * 1024 * 1024; // 8MB
    if (fileSize > maxFileSize) {
      throw new Error(`文件过大 (${(fileSize / 1024 / 1024).toFixed(2)}MB)，当前最大支持 8MB`);
    }

    logger.info("正在部署网站...");

    // 读取文件并转为 base64
    const fileContentBase64 = await this.readFileAsBase64(localFilePath);

    // 调用新的 mcp-api /deploy 端点
    const result = await this.callApi(
      "/deploy",
      {
        action: "upload_and_deploy",
        fileContentBase64,
        fileName: params.fileName,
        websiteId,
        projectId: params.projectId,
      },
      accessToken
    );

    logger.info(`网站部署成功: ${result.url}`);
    return result;
  }

  /**
   * 生成 8 位由大写字母与数字组成的随机 websiteId
   */
  private generateWebsiteId(): string {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let out = "";
    for (let i = 0; i < 8; i++) {
      out += chars[Math.floor(Math.random() * chars.length)];
    }
    return out;
  }

  /**
   * 获取路径状态信息
   */
  private async getPathStat(
    filePath: string
  ): Promise<{ isFile: boolean; isDirectory: boolean; size: number }> {
    const fs = await import("fs");

    if (!fs.existsSync(filePath)) {
      throw new Error(`路径不存在: ${filePath}`);
    }

    const stat = fs.statSync(filePath);
    return {
      isFile: stat.isFile(),
      isDirectory: stat.isDirectory(),
      size: stat.size,
    };
  }

  /**
   * 获取文件大小
   */
  private async getFileSize(filePath: string): Promise<number> {
    const stat = await this.getPathStat(filePath);
    return stat.size;
  }

  /**
   * 读取文件为 base64
   */
  private async readFileAsBase64(filePath: string): Promise<string> {
    const fs = await import("fs");

    try {
      const buffer = fs.readFileSync(filePath);
      const base64 = buffer.toString("base64");
      logger.debug(`文件读取成功，大小: ${buffer.length} 字节`);
      return base64;
    } catch (error: any) {
      throw new Error(`读取文件失败: ${error.message}`);
    }
  }

  /**
   * 将目录打包成 ZIP 文件
   */
  private async zipDirectoryToFile(dirPath: string): Promise<string> {
    const fs = await import("fs");
    const pathModule = await import("path");
    const os = await import("os");
    const AdmZip = await import("adm-zip");

    try {
      const zip = new AdmZip.default();
      zip.addLocalFolder(dirPath);

      // 保存到临时文件
      const tempFile = pathModule.join(
        os.tmpdir(),
        `demox-deploy-${Date.now()}.zip`
      );
      zip.writeZip(tempFile);

      logger.debug(`目录打包成功: ${dirPath} -> ${tempFile}`);
      return tempFile;
    } catch (error: any) {
      throw new Error(`打包目录失败: ${error.message}`);
    }
  }

  private async detectSourceProjectDirectory(dirPath: string): Promise<string | null> {
    const fs = await import("fs");
    const pathModule = await import("path");
    const exists = (name: string) => fs.existsSync(pathModule.join(dirPath, name));
    const isDir = (name: string) => {
      try {
        return fs.statSync(pathModule.join(dirPath, name)).isDirectory();
      } catch {
        return false;
      }
    };

    if (isDir("node_modules")) {
      return "检测到目录里包含 node_modules。请不要上传源码项目或依赖目录，请先运行 npm run build，然后部署 dist/build/out 目录。";
    }

    const hasPackage = exists("package.json");
    const hasLock = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb"].some(exists);
    const hasSourceDir = ["src", "app", "pages", "components"].some(isDir);
    const hasConfig = [
      "vite.config.js", "vite.config.ts", "vite.config.mjs",
      "next.config.js", "next.config.mjs", "nuxt.config.ts",
      "astro.config.mjs", "svelte.config.js", "webpack.config.js",
      "tailwind.config.js", "postcss.config.js"
    ].some(exists);

    let packageLooksFrontend = false;
    if (hasPackage) {
      try {
        const pkg = JSON.parse(fs.readFileSync(pathModule.join(dirPath, "package.json"), "utf8"));
        const deps = {
          ...(pkg.dependencies || {}),
          ...(pkg.devDependencies || {}),
          ...(pkg.peerDependencies || {}),
        };
        packageLooksFrontend = Object.keys(deps).some((name) =>
          /^(vite|next|nuxt|astro|svelte|react|react-dom|vue|@vitejs\/|@sveltejs\/|@astrojs\/|@angular\/|webpack|parcel|tailwindcss)$/i.test(name)
        ) || Boolean(pkg.scripts?.build || pkg.scripts?.dev || pkg.scripts?.start);
      } catch {
        packageLooksFrontend = true;
      }
    }

    if ((hasPackage && (packageLooksFrontend || hasSourceDir || hasConfig || hasLock)) || (hasConfig && hasSourceDir)) {
      return [
        "检测到你部署的是前端源码项目，而不是静态构建产物。",
        "Demox 当前只托管可直接访问的静态文件。",
        "请先在本地项目根目录运行 npm install && npm run build，",
        "然后部署构建输出目录，例如：demox deploy ./dist 或 demox deploy ./out。",
      ].join("\n");
    }
    return null;
  }

  /**
   * 下载 ZIP 文件并保存为 Buffer
   */
  private async downloadZipFileToBuffer(url: string): Promise<Buffer> {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`下载失败: ${response.statusText}`);
      }

      const buffer = Buffer.from(await response.arrayBuffer());
      logger.debug(`ZIP 文件下载成功，大小: ${buffer.length} 字节`);
      return buffer;
    } catch (error: any) {
      logger.error("下载 ZIP 文件失败:", error.message);
      throw error;
    }
  }

  /**
   * 保存 Buffer 到临时文件
   */
  private async saveBufferToTempFile(buffer: Buffer): Promise<string> {
    const fs = await import("fs");
    const pathModule = await import("path");
    const os = await import("os");

    const tempFile = pathModule.join(
      os.tmpdir(),
      `demox-download-${Date.now()}.zip`
    );

    fs.writeFileSync(tempFile, buffer);
    logger.debug(`Buffer 已保存到临时文件: ${tempFile}`);
    return tempFile;
  }

  /**
   * 检查字符串是否是 base64 编码
   */
  private isBase64(str: string): boolean {
    try {
      return btoa(atob(str)) === str;
    } catch (e) {
      return !str.includes("/") && !str.includes("\\") && str.length > 100;
    }
  }

  private buildDefaultUrl(websiteId: string): string {
    return websiteId ? `https://${websiteId.toLowerCase()}.demox.site/` : "";
  }

  private buildCustomUrl(subdomain?: string | null, domain?: string | null): string | null {
    const label = (subdomain || "").trim().toLowerCase();
    const suffix = (domain || "demox.site").trim().toLowerCase();
    return label ? `https://${label}.${suffix}/` : null;
  }

  private mapMySQLToCamelCase(row: any): Website {
    const websiteId = row.website_id || row.websiteId || "";
    const subdomain = row.subdomain || null;
    const subdomainDomain = row.subdomainDomain || row.subdomain_domain || "demox.site";
    const defaultUrl = row.defaultUrl || row.default_url || this.buildDefaultUrl(websiteId);
    const customUrl = row.customUrl || row.custom_url || this.buildCustomUrl(subdomain, subdomainDomain);
    const preferredUrl = row.preferredUrl || row.preferred_url || customUrl || defaultUrl || row.url || "";

    return {
      websiteId,
      fileName: row.file_name || row.fileName || "",
      name: row.name || row.file_name || row.fileName || "",
      path: row.path || "",
      url: preferredUrl,
      subdomain,
      subdomainDomain,
      projectId: row.project_id || row.projectId ? String(row.project_id || row.projectId) : null,
      projectName: row.project_name || row.projectName || null,
      projectSlug: row.project_slug || row.projectSlug || null,
      defaultUrl,
      customUrl,
      preferredUrl,
      createdAt: row.created_at || row.createdAt || "",
      updatedAt: row.updated_at || row.updatedAt || "",
    };
  }

  /**
   * 列出所有网站
   */
  async listWebsites(accessToken: string): Promise<Website[]> {
    logger.debug("获取网站列表");

    const result = await this.callApi(
      "/websites",
      { action: "list" },
      accessToken
    );

    const rawWebsites = result.files || result.websites || [];
    return rawWebsites.map((w: any) => this.mapMySQLToCamelCase(w));
  }

  async listProjects(accessToken: string): Promise<Project[]> {
    logger.debug("获取项目列表");
    const result = await this.callApi(
      "/website/list-projects",
      { action: "list_projects" },
      accessToken,
      this.websiteApiUrl
    );
    const rawProjects = result.projects || result.data || [];
    return rawProjects.map((p: any) => ({
      id: String(p.id || p._id),
      name: p.name || "default",
      slug: p.slug || "default",
      archived: !!p.archived,
      websitesCount: Number(p.websitesCount || p.websites_count || 0),
    }));
  }

  /**
   * 删除网站
   */
  async deleteWebsite(
    websiteId: string,
    accessToken: string
  ): Promise<void> {
    logger.info(`正在删除网站: ${websiteId}`);

    await this.callApi(
      "/delete",
      { websiteId },
      accessToken
    );

    logger.info("网站已删除");
  }

  /**
   * 获取网站详情
   */
  async getWebsite(
    websiteId: string,
    accessToken: string
  ): Promise<Website | null> {
    logger.debug(`获取网站详情: ${websiteId}`);

    // mcp-api 没有单独的 get 接口，从列表中查找
    const websites = await this.listWebsites(accessToken);
    return websites.find(w => w.websiteId === websiteId) || null;
  }

  async checkSubdomain(
    subdomain: string,
    accessToken: string,
    websiteId?: string,
    domain?: string
  ): Promise<DomainCheckResult> {
    return await this.callApi(
      "/website/check-subdomain",
      { action: "check_subdomain", subdomain, websiteId, domain },
      accessToken,
      this.websiteApiUrl
    );
  }

  async setSubdomain(
    websiteId: string,
    subdomain: string,
    accessToken: string,
    domain?: string
  ): Promise<DomainResult> {
    return await this.callApi(
      "/website/set-subdomain",
      { action: "set_subdomain", websiteId, subdomain, domain },
      accessToken,
      this.websiteApiUrl
    );
  }

  async clearSubdomain(
    websiteId: string,
    accessToken: string
  ): Promise<DomainResult> {
    return await this.callApi(
      "/website/clear-subdomain",
      { action: "clear_subdomain", websiteId },
      accessToken,
      this.websiteApiUrl
    );
  }

  /**
   * 验证 Token 有效性
   */
  async verifyToken(accessToken: string): Promise<boolean> {
    try {
      await this.callApi(
        "/me",
        {},
        accessToken
      );
      return true;
    } catch (error) {
      logger.error("Token 验证失败:", error);
      return false;
    }
  }
}
