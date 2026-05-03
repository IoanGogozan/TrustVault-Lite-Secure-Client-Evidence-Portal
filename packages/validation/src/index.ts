export const allowedDocumentExtensions = [".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx"] as const;

export type AllowedDocumentExtension = (typeof allowedDocumentExtensions)[number];

export function hasAllowedDocumentExtension(filename: string): boolean {
  const normalized = filename.toLowerCase();

  return allowedDocumentExtensions.some((extension) => normalized.endsWith(extension));
}

