import { realpathSync } from "node:fs";
import { isAbsolute, posix, relative, resolve, win32 } from "node:path";
import { pathToFileURL } from "node:url";

export function isContainedRelativePath(relativePath: string): boolean {
  return relativePath !== ".."
    && !relativePath.startsWith("../")
    && !relativePath.startsWith("..\\")
    && !isAbsolute(relativePath)
    && !posix.isAbsolute(relativePath)
    && !win32.isAbsolute(relativePath);
}

export function snapshotRuntimeModuleUrl(
  runtimeRoot: string,
  modulePath: string,
): string {
  const canonicalRoot = realpathSync(runtimeRoot);
  const canonicalModule = realpathSync(modulePath);
  const relativeModule = relative(canonicalRoot, canonicalModule);
  if (
    !isContainedRelativePath(relativeModule) ||
    resolve(canonicalRoot, relativeModule) !== canonicalModule
  ) {
    throw new Error("snapshot-runtime-module-outside-disposable-root");
  }
  return `${pathToFileURL(canonicalModule).href}?runtime=${Date.now()}`;
}
