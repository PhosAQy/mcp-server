import { loadConfig, logger } from "../utils/config.js";

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
  fileName: string;
}

/**
 * 部署结果
 */
export interface DeployResult {
  url: string;
  websiteId: string;
  path: string;
}

/**
 * 网站信息
 */
export interface Website {
  websiteId: string;
  fileName: string;
  url: string;
  path: string;
  createdAt: string;
  updatedAt: string;
}

/**
 * Demox API 客户端
 * 通过 mcp-api 云函数调用其他云函数
 */
export class DemoxClient {
  private cloudFunctionUrl: string;

  constructor(accessToken?: string) {
    const config = loadConfig();
    this.cloudFunctionUrl = config.cloudFunctionUrl;
  }

  /**
   * 调用云函数
   *
   * 使用 mcp-api 代理模式：需要 { functionName, data } 包装
   */
  private async callFunction(
    name: string,
    data: Record<string, any>,
    accessToken: string
  ): Promise<any> {
    const https = await import("https");
    const urlModule = await import("url");

    try {
      logger.debug(`调用云函数: ${name}`);
      logger.debug(`API URL: ${this.cloudFunctionUrl}`);

      // 使用 mcp-api 代理模式，将 accessToken 添加到 data 中
      const requestBody = {
        functionName: name,
        data: {
          ...data,
          accessToken, // 云函数需要从 data 中获取 accessToken
        },
      };
      logger.debug('使用代理调用模式');

      const urlObj = new urlModule.URL(this.cloudFunctionUrl);
      const requestBodyStr = JSON.stringify(requestBody);

      // 使用原生 https.request 并禁用 SSL 验证
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
            rejectUnauthorized: false, // 禁用 SSL 证书验证
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
            errorText.includes("AUTH_REQUIRED") ||
            errorText.includes("INVALID_CREDENTIALS")) {
          logger.error("鉴权失败，需要重新登录");
          throw new AuthError("Token 已过期或无效，需要重新登录");
        }

        throw new Error(`HTTP ${responseData.status}: ${errorText}`);
      }

      // 检查错误
      if (responseData.data && responseData.data.error) {
        const error = responseData.data.error;

        // 检查是否是鉴权相关的错误代码
        const authErrorCodes = [
          "TOKEN_INVALID",
          "AUTH_REQUIRED",
          "AUTH_ERROR",
          "UNAUTHORIZED",
          "TOKEN_EXPIRED",
          "NEED_LOGIN",
          "INVALID_CREDENTIALS",
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

      return responseData.data;
    } catch (error: any) {
      // 如果已经是 AuthError，直接抛出
      if (error instanceof AuthError) {
        throw error;
      }

      logger.error(`云函数调用失败 (${name}):`, error.message);
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

    // 从 token 中解析用户 ID（假设 accessToken 是 JWT）
    let userId = 'unknown';
    try {
      // JWT 格式: header.payload.signature
      const payload = accessToken.split('.')[1];
      if (payload) {
        const decoded = JSON.parse(Buffer.from(payload, 'base64').toString());
        userId = decoded.uid || decoded.user_id || decoded.userId || decoded.sub || 'unknown';
        logger.debug(`从 token 解析出用户 ID: ${userId}`);
      }
    } catch (error) {
      logger.warn('无法从 token 解析用户 ID，将使用默认值');
    }

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
      // Base64: 不再支持（无法验证文件类型）
      throw new Error(`不支持直接传入 Base64 内容，请提供 ZIP 文件路径或 URL`);
    } else {
      // 本地路径：文件或目录
      logger.debug(`检测到本地路径: ${params.zipFile}`);

      const stat = await this.getPathStat(params.zipFile);
      if (stat.isDirectory) {
        // 目录：打包成 ZIP
        logger.debug(`检测到目录: ${params.zipFile}，正在打包...`);
        localFilePath = await this.zipDirectoryToFile(params.zipFile);
      } else if (params.zipFile.toLowerCase().endsWith(".zip")) {
        // ZIP 文件：直接使用
        localFilePath = params.zipFile;
      } else {
        throw new Error(`不支持的文件类型，仅支持 .zip 文件或目录`);
      }
    }

    if (!localFilePath) {
      throw new Error(`无法处理输入文件`);
    }

    // 显示文件大小并检查限制
    const fileSize = await this.getFileSize(localFilePath);
    logger.info(`文件大小: ${(fileSize / 1024 / 1024).toFixed(2)}MB`);

    // 检查文件大小限制（最大 500MB，避免内存溢出）
    const maxFileSize = 500 * 1024 * 1024; // 500MB
    if (fileSize > maxFileSize) {
      throw new Error(`文件过大 (${(fileSize / 1024 / 1024).toFixed(2)}MB)，当前最大支持 500MB`);
    }

    logger.info("正在部署网站...");

    // 使用云存储上传方式
    logger.info(`文件大小: ${(fileSize / 1024 / 1024).toFixed(2)}MB，上传到云存储`);
    const uploadResult = await this.uploadToCloudStorage(localFilePath, accessToken);

    const result = await this.callFunction(
      "deploy-website",
      {
        action: "upload_and_deploy",
        fileId: uploadResult.fileId,
        websiteId,
        fileName: params.fileName,
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

  /**
   * 上传文件到云存储
   * 使用云函数获取上传凭证，然后直接上传到主存储桶
   */
  private async uploadToCloudStorage(
    filePath: string,
    accessToken: string
  ): Promise<{ fileId: string; objectId: string }> {
    const fs = await import("fs");
    const pathModule = await import("path");
    const https = await import("https");
    const urlModule = await import("url");

    const fileName = pathModule.basename(filePath);
    const fileSize = fs.statSync(filePath).size;

    logger.info(`准备上传文件: ${fileName} (${(fileSize / 1024 / 1024).toFixed(2)}MB)`);

    // 构建云端路径
    const cloudPath = `demox-deploy/${Date.now()}-${fileName}`;

    logger.debug(`调用云函数获取上传凭证: ${cloudPath}`);

    // 调用云函数获取上传凭证
    const uploadInfo = await this.callFunction(
      "deploy-website",
      {
        action: "get_upload_url",
        cloudPath,
      },
      accessToken
    );

    if (!uploadInfo.uploadUrl || !uploadInfo.fileId) {
      throw new Error("获取上传凭证失败");
    }

    logger.info(`上传凭证获取成功`);
    logger.debug(`上传 URL: ${uploadInfo.uploadUrl}`);
    logger.debug(`文件 ID: ${uploadInfo.fileId}`);

    // 读取文件内容
    const fileBuffer = fs.readFileSync(filePath);

    // 解析上传 URL
    const uploadUrl = new urlModule.URL(uploadInfo.uploadUrl);

    logger.info(`开始上传到 COS: ${uploadUrl.hostname}${uploadUrl.pathname}`);

    // 上传文件到 COS
    const uploadResult = await new Promise<{
      statusCode: number;
      headers: any;
      body: string;
    }>((resolve, reject) => {
      const req = https.request(
        {
          hostname: uploadUrl.hostname,
          port: 443,
          path: uploadUrl.pathname + uploadUrl.search,
          method: "PUT",
          headers: {
            "Content-Type": "application/zip",
            "Content-Length": fileBuffer.length,
          },
        },
        (res) => {
          let body = "";
          res.on("data", (chunk) => {
            body += chunk;
          });
          res.on("end", () => {
            resolve({
              statusCode: res.statusCode || 0,
              headers: res.headers,
              body,
            });
          });
        }
      );

      req.on("error", (err) => {
        logger.error("上传请求错误:", err);
        reject(err);
      });

      req.write(fileBuffer);
      req.end();
    });

    logger.debug(`上传响应状态码: ${uploadResult.statusCode}`);
    if (uploadResult.body) {
      logger.debug(`上传响应内容: ${uploadResult.body.substring(0, 500)}`);
    }

    // COS 上传成功返回 200
    if (uploadResult.statusCode !== 200) {
      logger.error(`上传失败，状态码: ${uploadResult.statusCode}`);
      logger.error(`响应内容: ${uploadResult.body}`);
      throw new Error(`文件上传失败: HTTP ${uploadResult.statusCode} - ${uploadResult.body}`);
    }

    logger.info(`文件上传成功到主存储桶`);
    logger.info(`文件 ID: ${uploadInfo.fileId}`);

    return {
      fileId: uploadInfo.fileId,
      objectId: uploadInfo.objectId || cloudPath,
    };
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
    // 简单的 base64 检测
    try {
      return btoa(atob(str)) === str;
    } catch (e) {
      // 如果不是 base64，检查是否是本地路径
      return !str.includes("/") && !str.includes("\\") && str.length > 100;
    }
  }

  /**
   * 列出所有网站
   */
  async listWebsites(accessToken: string): Promise<Website[]> {
    logger.debug("获取网站列表");

    const result = await this.callFunction(
      "deploy-website",
      {
        action: "list",
      },
      accessToken
    );

    // 云函数返回 { files: [...], count: n }
    return result.files || [];
  }

  /**
   * 删除网站
   */
  async deleteWebsite(
    websiteId: string,
    accessToken: string
  ): Promise<void> {
    logger.info(`正在删除网站: ${websiteId}`);

    await this.callFunction(
      "deploy-website",
      {
        action: "delete",
        websiteId,
      },
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

    const result = await this.callFunction(
      "deploy-website",
      {
        action: "get",
        websiteId,
      },
      accessToken
    );

    return result.website || null;
  }

  /**
   * 下载 ZIP 文件并转换为 base64
   */
  private async downloadZipFile(url: string): Promise<string> {
    try {
      const response = await fetch(url);
      if (!response.ok) {
        throw new Error(`下载失败: ${response.statusText}`);
      }

      const buffer = await response.arrayBuffer();
      const base64 = Buffer.from(buffer).toString("base64");

      logger.debug(`ZIP 文件下载成功，大小: ${buffer.byteLength} 字节`);
      return base64;
    } catch (error: any) {
      logger.error("下载 ZIP 文件失败:", error.message);
      throw error;
    }
  }

  /**
   * 验证 Token 有效性
   */
  async verifyToken(accessToken: string): Promise<boolean> {
    try {
      await this.callFunction(
        "oauth-token-manager",
        {
          action: "verify_token",
          accessToken,
        },
        accessToken
      );

      return true;
    } catch (error) {
      logger.error("Token 验证失败:", error);
      return false;
    }
  }
}
