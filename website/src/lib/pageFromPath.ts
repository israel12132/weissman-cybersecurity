export function pageIdFromDocument(): string {
  return document.documentElement.dataset.page || 'home'
}
