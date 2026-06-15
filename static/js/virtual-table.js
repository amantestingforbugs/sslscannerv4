const DEFAULT_CHUNK_SIZE = 150;

export function renderRowsIncrementally(tbody, rows, renderRow, { chunkSize = DEFAULT_CHUNK_SIZE } = {}) {
  if (!tbody) return Promise.resolve(0);
  tbody.replaceChildren();
  let index = 0;
  return new Promise((resolve) => {
    const pump = () => {
      const fragment = document.createDocumentFragment();
      const end = Math.min(index + chunkSize, rows.length);
      for (; index < end; index += 1) fragment.appendChild(renderRow(rows[index], index));
      tbody.appendChild(fragment);
      if (index < rows.length) requestAnimationFrame(pump);
      else resolve(rows.length);
    };
    pump();
  });
}

export function virtualizeTableBody(tbody, rows, renderRow, { rowHeight = 44, overscan = 8 } = {}) {
  const scroller = tbody?.closest('.table-wrap, .content, [data-virtual-scroll]');
  if (!tbody || !scroller || rows.length < 500) {
    return renderRowsIncrementally(tbody, rows, renderRow);
  }
  const topPad = document.createElement('tr');
  const bottomPad = document.createElement('tr');
  const render = () => {
    const visibleCount = Math.ceil(scroller.clientHeight / rowHeight) + overscan * 2;
    const start = Math.max(0, Math.floor(scroller.scrollTop / rowHeight) - overscan);
    const end = Math.min(rows.length, start + visibleCount);
    const frag = document.createDocumentFragment();
    topPad.style.height = `${start * rowHeight}px`;
    bottomPad.style.height = `${Math.max(0, rows.length - end) * rowHeight}px`;
    frag.appendChild(topPad);
    for (let i = start; i < end; i += 1) frag.appendChild(renderRow(rows[i], i));
    frag.appendChild(bottomPad);
    tbody.replaceChildren(frag);
  };
  scroller.addEventListener('scroll', render, { passive: true });
  render();
  return Promise.resolve(rows.length);
}
