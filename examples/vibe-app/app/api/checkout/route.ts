import Stripe from "stripe";
import { NextResponse } from "next/server";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  const { amount, customerId } = await request.json();

  const session = await stripe.checkout.sessions.create({
    mode: "payment",
    customer: customerId,
    line_items: [
      {
        price_data: {
          currency: "usd",
          unit_amount: amount,
          product_data: { name: "Credits" },
        },
        quantity: 1,
      },
    ],
    success_url: `${process.env.SITE_URL}/dashboard?paid=1`,
    cancel_url: `${process.env.SITE_URL}/dashboard`,
  });

  return NextResponse.json({ url: session.url });
}
