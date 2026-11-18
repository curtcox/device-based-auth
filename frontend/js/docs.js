/** Docs page: a copy button on every code block. */
import { copyButton } from './html.js';

for (const pre of document.querySelectorAll('.docs-body pre')) {
  const button = copyButton('Copy', () => pre.textContent, { class: 'secondary small copy-code', 'aria-label': 'Copy this code' });
  pre.before(button);
}
