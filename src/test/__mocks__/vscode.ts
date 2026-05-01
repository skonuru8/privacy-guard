type Disposable = { dispose: () => void };

const noopDisposable: Disposable = { dispose: () => {} };

export const window = {
  showInformationMessage: jest.fn(),
  showWarningMessage: jest.fn(),
  showErrorMessage: jest.fn(),
  registerWebviewViewProvider: jest.fn(() => noopDisposable),
};

export const commands = {
  registerCommand: jest.fn(() => noopDisposable),
};

export const workspace = {
  workspaceFolders: [
    {
      uri: { fsPath: "/tmp/workspace" },
    },
  ],
  getConfiguration: jest.fn(() => ({
    get: (_key: string, defaultValue: any) => defaultValue,
  })),
};

export class Uri {
  static file(fsPath: string) {
    return { fsPath };
  }
}

export type ExtensionContext = {
  extensionPath: string;
  subscriptions: Disposable[];
};

