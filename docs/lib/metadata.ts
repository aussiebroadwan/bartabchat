import type { Metadata } from 'next/types';

export function createMetadata(override: Metadata): Metadata {
  return {
    ...override,
  };
}

export const baseUrl = new URL('http://localhost:3000')