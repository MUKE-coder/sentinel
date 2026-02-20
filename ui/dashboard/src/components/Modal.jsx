export default function Modal({ isOpen, onClose, title, children }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-[#0d1526] border border-[#1e2d4a] rounded-lg w-full max-w-2xl max-h-[80vh] overflow-auto m-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d4a]">
          <h2 className="text-lg font-semibold text-[#e0e0e0]">{title}</h2>
          <button onClick={onClose} className="text-[#8892a0] hover:text-[#e0e0e0] text-xl">
            &times;
          </button>
        </div>
        <div className="p-6">{children}</div>
      </div>
    </div>
  );
}
