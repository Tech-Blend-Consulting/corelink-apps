export interface TransitClientOptions {
  transitUrl: string;
  platformUrl?: string;
  nhiId?: string;
  caCertFile?: string;
}

export interface Secret { name: string; value: string }
export interface Config { name: string; file_name: string; content: string }

export class TransitClient {
  constructor(options: TransitClientOptions);
  bootstrap(): Promise<void>;
  listSecrets(): Promise<Secret[]>;
  getSecret(name: string): Promise<string>;
  listConfigs(): Promise<Config[]>;
  getConfig(name: string): Promise<string>;
  close(): Promise<void>;
}

export class Watcher {
  constructor(client: TransitClient, intervalMs?: number);
  watchSecret(name: string, fn: (value: string) => void): void;
  watchConfig(name: string, fn: (content: string) => void): void;
  start(): void;
  stop(): void;
}

export function computeFingerprint(nhiId: string): {
  fingerprint: string;
  metadata: Record<string, string>;
};
