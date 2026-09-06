/** Fixed synthetic upstream. It is not exposed through a bypass route. */
export const ORDERS: Record<
  string,
  { id: string; owner: string; item: string; total: number; status: string }
> = {
  ord_1001: {
    id: 'ord_1001',
    owner: 'alice',
    item: 'Mechanical keyboard',
    total: 89,
    status: 'shipped',
  },
  ord_1002: {
    id: 'ord_1002',
    owner: 'bob',
    item: 'Studio headphones',
    total: 149,
    status: 'processing',
  },
};
export function profile(subject: string) {
  return {
    id: subject,
    name: subject === 'alice' ? 'Alice Morgan' : 'Bob Chen',
    email: `${subject}@example.test`,
    internalNote: 'SYNTHETIC: priority customer',
    passwordHash: 'SYNTHETIC_NOT_A_REAL_HASH',
    billingToken: 'SYNTHETIC_NOT_A_REAL_TOKEN',
  };
}
export function search(query: string) {
  const catalog = ['Mechanical keyboard', 'Studio headphones', 'USB-C hub'];
  return {
    results: catalog
      .filter((item) => item.toLowerCase().includes(query.toLowerCase()))
      .map((name, i) => ({ id: `product_${i + 1}`, name })),
  };
}
