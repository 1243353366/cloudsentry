import { describe, expect, it } from "vitest";
import { clearCustomerSessionCookies } from "./customer-auth";

type CookieCall = { name: string; options: Record<string, unknown> };

describe("managed customer logout cookies", () => {
  it("clears both the revocable workspace cookie and validated managed app cookie", () => {
    const cleared: CookieCall[] = [];
    clearCustomerSessionCookies({
      clearCookie: (name: string, options: Record<string, unknown>) => cleared.push({ name, options }),
    } as never);

    expect(cleared.map(call => call.name)).toEqual(["CS_operator_session", "webdev_app_session"]);
    for (const call of cleared) {
      expect(call.options).toMatchObject({ secure: true, sameSite: "none", httpOnly: true, path: "/" });
    }
  });
});
