interface Item {
  name: string;
  price: number;
  image: string;
  amount: number;
  product: string;
}

interface Order {
  tax: number;
  shippingFee: number;
  items: Item[];
}

export const orders: Order[] = [
  {
    tax: 399,
    shippingFee: 499,
    items: [
      {
        name: 'accent chair',
        price: 2599,
        image:
          'https://dl.airtable.com/.attachmentThumbnails/e8bc3791196535af65f40e36993b9e1f/438bd160',
        amount: 34,
        product: '6126ad3424d2bd09165a68c8',
      },
    ],
  },
  {
    tax: 499,
    shippingFee: 799,
    items: [
      {
        name: 'bed',
        price: 2699,
        image:
          'https://dl.airtable.com/.attachmentThumbnails/e8bc3791196535af65f40e36993b9e1f/438bd160',
        amount: 3,
        product: '6126ad3424d2bd09165a68c7',
      },
      {
        name: 'chair',
        price: 2999,
        image:
          'https://dl.airtable.com/.attachmentThumbnails/e8bc3791196535af65f40e36993b9e1f/438bd160',
        amount: 2,
        product: '6126ad3424d2bd09165a68c4',
      },
    ],
  },
];
