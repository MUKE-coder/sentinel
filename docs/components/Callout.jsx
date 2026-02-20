import { AlertTriangle, Info, CheckCircle, XCircle } from 'lucide-react';
import clsx from 'clsx';

const variants = {
  info: {
    icon: Info,
    container: 'bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800',
    icon_color: 'text-blue-500',
    title_color: 'text-blue-800 dark:text-blue-300',
  },
  warning: {
    icon: AlertTriangle,
    container: 'bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800',
    icon_color: 'text-amber-500',
    title_color: 'text-amber-800 dark:text-amber-300',
  },
  success: {
    icon: CheckCircle,
    container: 'bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800',
    icon_color: 'text-green-500',
    title_color: 'text-green-800 dark:text-green-300',
  },
  danger: {
    icon: XCircle,
    container: 'bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800',
    icon_color: 'text-red-500',
    title_color: 'text-red-800 dark:text-red-300',
  },
};

export default function Callout({ type = 'info', title, children }) {
  const v = variants[type];
  const Icon = v.icon;

  return (
    <div className={clsx('my-4 rounded-lg border p-4', v.container)}>
      <div className="flex items-start gap-3">
        <Icon size={18} className={clsx('mt-0.5 flex-shrink-0', v.icon_color)} />
        <div>
          {title && <p className={clsx('font-semibold text-sm mb-1', v.title_color)}>{title}</p>}
          <div className="text-sm text-gray-700 dark:text-gray-300">{children}</div>
        </div>
      </div>
    </div>
  );
}
