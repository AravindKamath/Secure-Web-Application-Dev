import { TableCell } from "@windmill/react-ui";
import { format, parseISO } from "date-fns";
import { formatCurrency } from "helpers/formatCurrency";

const OrderItem = ({ order }) => {
  const getStatusBadge = (status) => {
    const normalized = status?.toLowerCase() || "";
    
    if (normalized === "pending") {
      return "bg-amber-100 text-amber-800 dark:bg-amber-950/40 dark:text-amber-400 border border-amber-200/50 dark:border-amber-900/50";
    }
    if (normalized === "paid" || normalized === "completed") {
      return "bg-green-100 text-green-800 dark:bg-green-950/40 dark:text-green-450 border border-green-200/50 dark:border-green-900/50";
    }
    if (normalized === "cancelled") {
      return "bg-red-100 text-red-800 dark:bg-red-950/40 dark:text-red-400 border border-red-200/50 dark:border-red-900/50";
    }
    if (normalized === "processing") {
      return "bg-blue-100 text-blue-800 dark:bg-blue-950/40 dark:text-blue-400 border border-blue-200/50 dark:border-blue-900/50";
    }
    if (normalized === "delivered") {
      return "bg-emerald-100 text-emerald-800 dark:bg-emerald-950/40 dark:text-emerald-450 border border-emerald-200/50 dark:border-emerald-900/50";
    }
    
    return "bg-neutral-100 text-neutral-800 dark:bg-neutral-800/40 dark:text-neutral-450 border border-neutral-200/50 dark:border-neutral-700/50";
  };

  const formattedItemsCount = `${order.total || 0} ${order.total === 1 ? "Item" : "Items"}`;

  return (
    <>
      {/* Order ID Badge */}
      <TableCell className="py-4 px-6 align-middle">
        <span className="inline-flex items-center px-2.5 py-1 rounded-lg text-xs font-semibold bg-neutral-100 dark:bg-neutral-800 text-neutral-700 dark:text-neutral-300 border border-neutral-200/60 dark:border-neutral-700/50 select-none">
          #{order.order_id}
        </span>
      </TableCell>

      {/* Items Count */}
      <TableCell className="py-4 px-6 align-middle text-sm font-semibold text-neutral-800 dark:text-neutral-200">
        {formattedItemsCount}
      </TableCell>

      {/* Status Badge */}
      <TableCell className="py-4 px-6 align-middle">
        <span className={`inline-flex items-center px-3 py-1 rounded-full text-xs font-bold tracking-wide capitalize ${getStatusBadge(order.status)}`}>
          {order.status}
        </span>
      </TableCell>

      {/* Amount (visually prominent & bold) */}
      <TableCell className="py-4 px-6 align-middle text-base font-black text-neutral-950 dark:text-white">
        {formatCurrency(order.amount)}
      </TableCell>

      {/* Date (lighter secondary text styling) */}
      <TableCell className="py-4 px-6 align-middle text-sm font-medium text-neutral-450 dark:text-neutral-500">
        {format(parseISO(order.date), "dd/MM/yy")}
      </TableCell>
    </>
  );
};

export default OrderItem;
