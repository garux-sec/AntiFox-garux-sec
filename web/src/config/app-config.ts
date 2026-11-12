import packageJson from "../../package.json";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "AntiFox",
  version: packageJson.version,
  copyright: `© ${currentYear}, AntiFox.`,
  meta: {
    title: "AntiFox — Autonomous Pentest Console",
    description: "AI-Driven Autonomous Penetration Testing Platform",
  },
};
