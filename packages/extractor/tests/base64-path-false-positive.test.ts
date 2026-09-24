import { extractFeatureVector, FEATURE_NAMES, CanonicalRequest } from "../src/index";

function vectorFor(req: Partial<CanonicalRequest>): number[] {
  return extractFeatureVector(req);
}

const BASE64_IDX = FEATURE_NAMES.indexOf("base64_like_count");

describe("base64_like_count", () => {
  test("REST path with UUID id no longer false-triggers", () => {
    const vec = vectorFor({
      method: "GET",
      path: "/api/v1/tokens/d7e805da-846a-32c3-bb81-e3c29b621792",
      query: "",
      body: "",
      userAgent: "node-fetch/3.3.2",
    });
    expect(vec[BASE64_IDX]).toBe(0);
  });

  test("deep REST path with long numeric id no longer false-triggers", () => {
    const vec = vectorFor({
      method: "GET",
      path: "/admin/users/123456789012345/permissions",
      query: "",
      body: "",
    });
    expect(vec[BASE64_IDX]).toBe(0);
  });

  test("real base64-encoded payload (no slashes) still matches", () => {
    const vec = vectorFor({
      method: "GET",
      path: "/download",
      query: `data=${"dGhpcyBpcyBhIHRlc3Qgb2YgYmFzZTY0IGVuY29kaW5nMTIzNDU2Nzg5MA=="}`,
      body: "",
    });
    expect(vec[BASE64_IDX]).toBeGreaterThan(0);
  });

  test("real base64 payload containing a literal '/' character still matches on the non-slash run", () => {
    // Real base64 alphabets do use '+' and '/' - only path-shaped '/' runs
    // are excluded. A base64 blob with an embedded '/' still has >= 20
    // contiguous alnum/+ characters on either side of it in practice; this
    // fixture keeps a 24-char unbroken run before the '/' to confirm that
    // case still matches even though the class no longer includes '/'.
    const vec = vectorFor({
      method: "GET",
      path: "/download",
      query: `data=QUJDREVGR0hJSktMTU5PUFFSU1RVVg/QUJDREVGR0hJSktMTU5PUFFSU1RVVg==`,
      body: "",
    });
    expect(vec[BASE64_IDX]).toBeGreaterThan(0);
  });
});
