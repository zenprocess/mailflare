import { buildMailFrameDocument, MAIL_FRAME_MESSAGE_SOURCE } from "/frame.js";
const BLANK = "data:image/gif;base64,R0lGODlhAQABAAD/ACwAAAAAAQABAAACADs=";
const results = { phases: [], violations: [] };
document.addEventListener("securitypolicyviolation", (e) => { results.violations.push(e.violatedDirective + " " + e.blockedURI); });
function longBody() {
  let h = "";
  for (let i = 0; i < 80; i++) h += "<p>Paragraph " + i + " makes this body much taller than the default iframe height of 150 pixels.</p>";
  return h;
}
function runPhase(includeRemote) {
  return new Promise((resolve) => {
    const body = longBody()
      + '<img data-mf-blob="0" src="' + BLANK + '" alt="cid" width="8" height="8">'
      + (includeRemote ? '<img data-mf-blob="1" src="' + BLANK + '" alt="remote" width="8" height="8">' : "");
    const srcdoc = buildMailFrameDocument(body, false, false);
    const frame = document.createElement("iframe");
    frame.setAttribute("sandbox", "allow-scripts allow-popups allow-popups-to-escape-sandbox");
    frame.setAttribute("referrerpolicy", "no-referrer");
    frame.setAttribute("data-phase", includeRemote ? "remote-on" : "remote-off");
    frame.style.width = "100%";
    frame.style.border = "0";
    const heights = [];
    let remoteFetched = 0;
    const onMessage = (event) => {
      if (event.source !== frame.contentWindow) return;
      const d = event.data;
      if (d && d.source === MAIL_FRAME_MESSAGE_SOURCE && d.type === "height") heights.push(d.height);
    };
    window.addEventListener("message", onMessage);
    frame.onload = async () => {
      const blobs = [];
      const urls = ["/cid.png"];
      if (includeRemote) urls.push("/remote.png");
      for (let i = 0; i < urls.length; i++) {
        try {
          const resp = await fetch(urls[i]);
          if (!resp.ok) continue;
          blobs.push({ index: i, blob: await resp.blob() });
          if (i === 1) remoteFetched = 1;
        } catch (e) {}
      }
      if (blobs.length) frame.contentWindow.postMessage({ source: MAIL_FRAME_MESSAGE_SOURCE, type: "blobs", blobs: blobs }, "*");
      await new Promise((r) => setTimeout(r, 500));
      window.removeEventListener("message", onMessage);
      let opacity = "unknown";
      try { const d = frame.contentWindow.document; void d; opacity = "readable"; } catch (e) { opacity = e.name; }
      resolve({ includeRemote: includeRemote, heights: heights, maxHeight: heights.length ? Math.max.apply(null, heights) : 0, sandbox: frame.getAttribute("sandbox"), opacity: opacity, remoteFetched: remoteFetched });
    };
    document.body.appendChild(frame);
    frame.srcdoc = srcdoc;
  });
}
(async () => {
  results.phases.push(await runPhase(false));
  results.phases.push(await runPhase(true));
  window.__MAILFRAME_RESULT = results;
})();
