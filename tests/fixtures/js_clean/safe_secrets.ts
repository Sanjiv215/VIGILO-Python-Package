// Safe Secrets & Environment Handling

// Safe 1: Loading from process.env
export const API_KEY = process.env.API_KEY || '';

// Safe 2: Loading from Vite import.meta.env
export const VITE_ENDPOINT = import.meta.env.VITE_API_ENDPOINT;

// Safe 3: Explicit placeholder value
export const DUMMY_API_KEY = 'your-api-key-here';

// Safe 4: Generic non-sensitive config
export const APP_TITLE = 'Vigilo Web Dashboard';
