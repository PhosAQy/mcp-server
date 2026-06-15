/**
 * 配置管理模块
 */

import os from "os";
import path from "path";

export interface MCPConfig {
  clientId: string;
  siteUrl: string;
  authUrl: string;
  apiBase: string;
  serverEnv: string;
  cloudFunctionUrl: string;
  websiteApiUrl: string;
}

function optionalEnv(name: string): string {
  return (process.env[name] || "").trim();
}

function requireEnv(name: string): string {
  const value = optionalEnv(name);
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return stripTrailingSlash(value);
}

function stripTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

export function loadConfig(): MCPConfig {
  const clientId = process.env.DEMOX_CLIENT_ID || "demox-mcp-client";
  const siteUrl = requireEnv("DEMOX_SITE_URL");
  const authUrl =
    stripTrailingSlash(optionalEnv("DEMOX_AUTH_URL") || `${siteUrl}/mcp-authorize`);
  const apiBase = stripTrailingSlash(optionalEnv("DEMOX_API_BASE") || siteUrl);
  const serverEnv = process.env.DEMOX_SERVER_ENV || "demox-scf";
  const apiUrl = stripTrailingSlash(
    optionalEnv("DEMOX_API_URL") ||
    optionalEnv("DEMOX_CLOUD_FUNCTION_URL") ||
    optionalEnv("DEMOX_WEBSITE_API_URL")
  );
  if (!apiUrl) {
    throw new Error("Missing required environment variable: DEMOX_API_URL");
  }
  const cloudFunctionUrl = stripTrailingSlash(optionalEnv("DEMOX_CLOUD_FUNCTION_URL") || apiUrl);
  const websiteApiUrl = stripTrailingSlash(optionalEnv("DEMOX_WEBSITE_API_URL") || apiUrl);

  return {
    clientId,
    siteUrl,
    authUrl,
    apiBase,
    serverEnv,
    cloudFunctionUrl,
    websiteApiUrl,
  };
}

/**
 * Token 存储路径
 */
export function getTokenPath(): string {
  const platform = os.platform();

  let configDir: string;

  if (platform === "darwin") {
    // macOS
    configDir = path.join(os.homedir(), ".demox");
  } else if (platform === "win32") {
    // Windows
    configDir = path.join(os.homedir(), ".demox");
  } else {
    // Linux
    configDir = path.join(os.homedir(), ".demox");
  }

  return path.join(configDir, "token.json");
}

/**
 * 日志工具
 */
export class Logger {
  private debugMode: boolean;

  constructor() {
    this.debugMode = process.env.DEBUG === "demox:*" || process.env.DEBUG === "*";
  }

  debug(message: string, ...args: any[]) {
    if (this.debugMode) {
      console.error(`[DEBUG] ${message}`, ...args);
    }
  }

  info(message: string, ...args: any[]) {
    console.error(`[INFO] ${message}`, ...args);
  }

  warn(message: string, ...args: any[]) {
    console.error(`[WARN] ${message}`, ...args);
  }

  error(message: string, ...args: any[]) {
    console.error(`[ERROR] ${message}`, ...args);
  }
}

export const logger = new Logger();
