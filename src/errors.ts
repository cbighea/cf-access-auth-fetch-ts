class AuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class MetadataError extends AuthError {}

export class OAuthError extends AuthError {
  readonly error?: string;
  readonly status?: number;

  constructor(message: string, options: { error?: string; status?: number } = {}) {
    super(message);
    this.error = options.error;
    this.status = options.status;
  }
}

export class InteractionRequiredError extends OAuthError {}
