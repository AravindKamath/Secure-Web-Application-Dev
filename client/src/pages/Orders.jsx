import {
  Pagination,
  Table,
  TableBody,
  TableCell,
  TableHeader,
  TableRow,
} from "@windmill/react-ui";
import OrderItem from "components/OrderItem";
import { useOrders } from "context/OrderContext";
import Layout from "layout/Layout";
import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Package } from "react-feather";
import orderService from "services/order.service";

const Orders = () => {
  const { orders, setOrders } = useOrders();
  const [currentPage, setCurrentPage] = useState(1);
  const navigate = useNavigate();

  const handlePage = (num) => {
    setCurrentPage(num);
  };

  const goToDetails = (order) => {
    navigate(`/orders/${order.order_id}`, { state: { order } });
  };

  useEffect(() => {
    orderService.getAllOrders(currentPage).then((res) => setOrders(res.data));
  }, [currentPage, setOrders]);

  if (orders !== null && (orders.length === 0 || orders.items?.length === 0 || orders.total === 0)) {
    return (
      <Layout title="Orders" loading={false}>
        <div className="w-full min-h-[75vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center justify-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl animate-fade-in">
          {/* Background glow matching Vantage theme */}
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />
          
          <div className="max-w-md w-full text-center p-8 rounded-3xl border border-neutral-200/80 bg-white/70 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20 flex flex-col items-center gap-6 z-10">
            <div className="w-16 h-16 rounded-full bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center text-neutral-400 dark:text-neutral-500 shadow-inner">
              <Package size={30} />
            </div>
            <div>
              <h2 className="text-2xl font-extrabold tracking-tight text-neutral-955 dark:text-white">
                No Orders Yet
              </h2>
              <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400 leading-relaxed">
                You haven't placed any orders yet. Start shopping to see your order history here.
              </p>
            </div>
            <Link
              to="/"
              className="w-full px-6 py-3 rounded-xl bg-[#01A982] text-white hover:bg-[#019371] font-semibold shadow-lg transition-all duration-300 hover:scale-[1.02] active:scale-95 text-center"
            >
              Continue Shopping
            </Link>
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout title="Orders" loading={orders === null}>
      <div className="w-full min-h-[85vh] bg-white text-black transition-colors duration-300 dark:bg-[#0a0a0a] dark:text-white flex flex-col items-center py-12 px-4 sm:px-6 lg:px-8 relative overflow-hidden rounded-3xl">
        {/* Background glow matching Vantage theme */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,rgba(0,0,0,0.03),transparent_60%)] dark:bg-[radial-gradient(circle_at_top,rgba(255,255,255,0.05),transparent_60%)] pointer-events-none" />

        <div className="relative w-full max-w-6xl z-10 flex flex-col gap-8 animate-fade-in">
          
          {/* Header */}
          <div className="text-center mb-2">
            <h1 className="text-4xl font-extrabold tracking-tight text-neutral-955 dark:text-white sm:text-5xl">
              My Orders
            </h1>
            <p className="mt-2 text-sm text-neutral-500 dark:text-neutral-400">
              Track and manage your purchases
            </p>
          </div>

          {/* Table Container */}
          <div className="overflow-x-auto rounded-3xl border border-neutral-200/80 bg-white/70 shadow-xl backdrop-blur-xl dark:border-white/10 dark:bg-neutral-900/60 transition-all duration-300 hover:border-neutral-300 dark:hover:border-white/20">
            <Table className="w-full min-w-[700px]">
              <TableHeader className="bg-neutral-50/60 dark:bg-neutral-950/30 border-b border-neutral-200/60 dark:border-neutral-800/60">
                <TableRow>
                  <TableCell className="py-4 px-6 text-xs font-extrabold uppercase tracking-widest text-neutral-450 dark:text-neutral-500">ID</TableCell>
                  <TableCell className="py-4 px-6 text-xs font-extrabold uppercase tracking-widest text-neutral-450 dark:text-neutral-500">No. of items</TableCell>
                  <TableCell className="py-4 px-6 text-xs font-extrabold uppercase tracking-widest text-neutral-450 dark:text-neutral-500">Status</TableCell>
                  <TableCell className="py-4 px-6 text-xs font-extrabold uppercase tracking-widest text-neutral-450 dark:text-neutral-500">Amount</TableCell>
                  <TableCell className="py-4 px-6 text-xs font-extrabold uppercase tracking-widest text-neutral-450 dark:text-neutral-500">Date</TableCell>
                </TableRow>
              </TableHeader>
              <TableBody className="divide-y divide-neutral-200/40 dark:divide-neutral-800/40 bg-transparent">
                {orders?.items.map((order) => (
                  <TableRow
                    className="cursor-pointer hover:bg-neutral-50/50 dark:hover:bg-neutral-950/20 transition-all duration-200"
                    onClick={() => goToDetails(order)}
                    key={order.order_id}
                  >
                    <OrderItem order={order} />
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <div className="flex justify-end items-center py-4 px-6 border-t border-neutral-200/60 dark:border-neutral-800/60 bg-transparent">
              <Pagination
                totalResults={orders?.total}
                resultsPerPage={5}
                onChange={handlePage}
                label="Table navigation"
              />
            </div>
          </div>

        </div>
      </div>
    </Layout>
  );
};

export default Orders;
