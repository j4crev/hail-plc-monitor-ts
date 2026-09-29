import { describe, expect, it, vi } from "vitest";
import { BoundedMonitorPlcClient } from "../src/plc.js";
import { assertWebhookUrl } from "../src/monitor.js";
import { PinnedHttpsAlertTransport, publicAddress } from "../src/notifier.js";

const did = `did:plc:${"a".repeat(24)}`;

describe("monitor network boundaries", () => {
  it("pins reads to the configured PLC origin, rejects redirects and bounds export pages", async () => {
    const request = vi.fn<(url: string, init: RequestInit) => Promise<Response>>(async () => new Response(""));
    const client = new BoundedMonitorPlcClient("https://plc.directory/", request, 50, 1024);
    expect(await client.exportAfter(5, 20)).toEqual([]);
    expect(request.mock.calls[0]?.[0]).toBe("https://plc.directory/export?after=5&count=20");
    expect(request.mock.calls[0]?.[1]).toMatchObject({ method: "GET", redirect: "error" });
    await expect(client.exportAfter(-1, 1)).rejects.toThrow("range");
    await expect(client.exportAfter(5, 1001)).rejects.toThrow("range");
    expect(request).toHaveBeenCalledOnce();
  });

  it("rejects duplicate JSON, excessive streamed bytes and hung PLC headers", async () => {
    const duplicate = new BoundedMonitorPlcClient("https://plc.directory", async () =>
      new Response('[{"a":1,"a":2}]'), 40, 128);
    await expect(duplicate.getOperationLog(did)).rejects.toThrow("Duplicate");
    const huge = new BoundedMonitorPlcClient("https://plc.directory", async () =>
      new Response(new Uint8Array(129)), 40, 128);
    await expect(huge.getOperationLog(did)).rejects.toThrow("limit");
    const stalled = new BoundedMonitorPlcClient("https://plc.directory",
      () => new Promise(() => {}), 15, 128);
    await expect(stalled.getOperationLog(did)).rejects.toMatchObject({ name: "TimeoutError" });
  });

  it("permits only public DNS-pinned HTTPS webhook targets without query credentials", async () => {
    expect(publicAddress("1.1.1.1")).toBe(true);
    expect(publicAddress("127.0.0.1")).toBe(false);
    expect(publicAddress("::ffff:127.0.0.1")).toBe(false);
    expect(() => assertWebhookUrl("https://user.example.com/hook?token=secret")).toThrow();
    expect(() => assertWebhookUrl("https://127.0.0.1/hook")).toThrow();
    const transport = new PinnedHttpsAlertTransport(async () => [{ address: "10.0.0.1", family: 4 }]);
    await expect(transport.send("https://user.example.com/hook", new Uint8Array([1]),
      new Uint8Array(64), "did:key:zvalid")).rejects.toThrow("exclusively public");
  });
});
