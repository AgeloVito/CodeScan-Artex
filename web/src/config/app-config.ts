import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "SCA Audit",
  version: packageJson.version,
  copyright: `© ${currentYear}, SCA Audit.`,
  meta: {
    title: "SCA Audit — 代码审计平台",
    description: "LLM 驱动的源代码安全审计平台控制台",
  },
};
