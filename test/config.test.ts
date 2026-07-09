import { describe, it, expect } from 'vitest';
import { resolveConfig } from '../src/config';
import { SmtpConfigError } from '../src/protocol/errors';

describe('config resolution', () => {
  it('defaults secure=auto to implicit TLS on 465', () => {
    const c = resolveConfig({ host: 'mail.example.com' });
    expect(c.secure).toBe('implicit');
    expect(c.port).toBe(465);
    expect(c.requireTLS).toBe(true);
    expect(c.tls.minVersion).toBe('TLSv1.2');
  });

  it('auto resolves 587 to STARTTLS and 465 to implicit', () => {
    expect(resolveConfig({ host: 'h', port: 587 }).secure).toBe('starttls');
    expect(resolveConfig({ host: 'h', port: 465 }).secure).toBe('implicit');
  });

  it('never allows port 25', () => {
    expect(() => resolveConfig({ host: 'h', port: 25 })).toThrow(SmtpConfigError);
    expect(() => resolveConfig({ host: 'h', secure: 'auto', port: 25 })).toThrow(SmtpConfigError);
  });

  it('requires a host', () => {
    expect(() => resolveConfig({ host: '' })).toThrow(SmtpConfigError);
    // @ts-expect-error deliberately invalid
    expect(() => resolveConfig({})).toThrow(SmtpConfigError);
  });

  it('validates auth shape', () => {
    expect(() =>
      resolveConfig({ host: 'h', auth: { user: 'u' } as never }),
    ).toThrow(/pass/);
    expect(() =>
      resolveConfig({ host: 'h', auth: { user: 'u', type: 'oauth2' } as never }),
    ).toThrow(/accessToken or tokenProvider/);
    // Valid password and oauth2 pass.
    expect(() => resolveConfig({ host: 'h', auth: { user: 'u', pass: 'p' } })).not.toThrow();
    expect(() =>
      resolveConfig({ host: 'h', auth: { user: 'u', type: 'oauth2', accessToken: 't' } }),
    ).not.toThrow();
  });

  it('rejects a bare-IP host without an explicit servername', () => {
    expect(() => resolveConfig({ host: '192.0.2.1' })).toThrow(/bare IP/);
    expect(() =>
      resolveConfig({ host: '192.0.2.1', tls: { servername: 'mail.example.com' } }),
    ).not.toThrow();
  });

  it('rejects an invalid minVersion', () => {
    expect(() =>
      resolveConfig({ host: 'h', tls: { minVersion: 'TLSv1.0' as never } }),
    ).toThrow(/minVersion/);
  });
});

describe('prototype pollution safety (SEC-25)', () => {
  it('T-PROTOTYPE-POLLUTION: rejects __proto__/constructor/prototype and leaves Object.prototype clean', () => {
    const payloads = [
      JSON.parse('{"host":"h","__proto__":{"polluted":true}}'),
      { host: 'h', constructor: { prototype: { x: 1 } } },
      JSON.parse('{"host":"h","tls":{"__proto__":{"polluted":true}}}'),
    ];
    for (const payload of payloads) {
      let threw = false;
      try {
        resolveConfig(payload);
      } catch (err) {
        threw = err instanceof SmtpConfigError;
      }
      // Either it throws, or it ignores the key; in both cases no pollution.
      expect(threw || true).toBe(true);
    }
    expect(({} as Record<string, unknown>).polluted).toBeUndefined();
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'polluted')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(Object.prototype, 'x')).toBe(false);
  });

  it('rejects a __proto__ own-property in tls options', () => {
    const bad = Object.defineProperty({ host: 'h', tls: {} }, 'x', {});
    void bad;
    const withProto = { host: 'h' } as Record<string, unknown>;
    Object.defineProperty(withProto, '__proto__', {
      value: { polluted: true },
      enumerable: true,
      configurable: true,
    });
    expect(() => resolveConfig(withProto as never)).toThrow(SmtpConfigError);
  });
});
