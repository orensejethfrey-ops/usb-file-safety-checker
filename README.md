# USB File Safety Checker

A static, browser-only file review page. It can flag selected files with common executable/script extensions, `autorun.inf`, some multiple-extension names, and archives whose contents were not inspected.

## Important limitations

This is **not antivirus software**. It does not read file contents, identify malware, inspect archive contents, or prove that any file is safe. “No obvious flags” only means that none of the basic filename rules matched.

The page has no server code or external dependencies. File names, paths, and content are not uploaded or sent to a scanning provider. To scan the complete USB drive, use up-to-date antivirus software installed on your computer.

## Run locally

Open `index.html` in a current desktop browser. Insert the USB drive, then choose its files or a folder from the page. A browser file picker requires the user to select files; the page cannot access a drive automatically.

## Publish on GitHub Pages

1. Push the contents of this folder to a GitHub repository.
2. In the repository, open **Settings → Pages**.
3. Under **Build and deployment**, choose **Deploy from a branch**, select `main` and `/ (root)`, then save.
4. Wait for the Pages deployment and open the URL shown in the Pages settings.

The published page remains a static site: it does not gain access to the full USB drive or perform antivirus scanning.
