// TypeScript typings for ssrf

declare namespace SSRF {
  interface ListOptions {
    // Back-compat file path
    blacklist?: string
    // File-based lists
    blacklistFile?: string
    whitelistFile?: string
    // Array-based lists
    blacklistHosts?: string[]
    blacklistIPs?: string[]
    blacklistCIDRs?: string[]
    whitelistHosts?: string[]
    whitelistIPs?: string[]
    whitelistCIDRs?: string[]
    // Return full href (true) or scheme+host (false). Default: true
    path?: boolean
  }

  type SourceKey = 'body' | 'query' | 'params' | 'headers'

  interface MiddlewareOptions {
    source?: SourceKey
    key?: string
    attachKey?: string
    replaceOriginal?: boolean
    blockOnError?: boolean
    statusCode?: number
    onError?: (errors: Array<Record<string, any>>, req: any, res: any, next: (err?: any) => void) => any
  }

  interface Instance {
    url(input: string): Promise<string>
    middleware(mwOptions?: MiddlewareOptions): any // Express.RequestHandler
  }
}

declare const ssrf: {
  // Global-style configuration (backward compatible)
  options(opts?: SSRF.ListOptions): void
  url(input: string): Promise<string>

  // Isolated instance factory
  create(options?: SSRF.ListOptions): SSRF.Instance

  // App-level convenience middleware
  middleware(options?: SSRF.ListOptions, mwOptions?: SSRF.MiddlewareOptions): any // Express.RequestHandler
}

export = ssrf
