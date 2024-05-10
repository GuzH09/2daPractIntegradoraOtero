import { Router } from "express";
import CartManagerDB from '../dao/CartManagerDB.js';
import ProductManagerDB from '../dao/ProductManagerDB.js';

const cartsRouter = Router();
const CM = new CartManagerDB();
const PM = new ProductManagerDB();

// Create New Empty Cart
cartsRouter.post('/', async (req, res) => {
    const result = await CM.addCart();
    result['success'] ? res.status(201).send(result) : res.status(400).send({error: "Cart couldn't be created."});
});

// Get Cart By Id
cartsRouter.get('/:cid', async (req, res) => {
    let cartId = req.params.cid;
    const carts = await CM.getCartById(cartId);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// Add Product to Cart
cartsRouter.post('/:cid/product/:pid', async (req, res) => {
    let cartId = req.params.cid;
    let productId = req.params.pid;
    const product = await PM.getProductById(productId);
    if ( product['error'] ) return res.status(400).send(product);
    const result = await CM.AddProductToCart(cartId, productId);
    result['success'] ? res.status(201).send(result) : res.status(400).send(result);
});

// Delete All Products From Cart
cartsRouter.delete('/:cid', async (req, res) => {
    let cartId = req.params.cid;
    const carts = await CM.emptyCartById(cartId);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// Delete Single Product From Cart
cartsRouter.delete('/:cid/product/:pid', async (req, res) => {
    let cartId = req.params.cid;
    let productId = req.params.pid;
    // Se creo el metodo deleteProductFromCart en el CartManager
    const carts = await CM.deleteProductFromCart(cartId, productId);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// PUT Single Cart With Products Object
cartsRouter.put('/:cid', async (req, res) => {
    let { products } = req.body;
    let cartId = req.params.cid;
    // For loop, for every product id in products array
    for (const item of products) {
        const productId = item.product;
        const product = await PM.getProductById(productId);
        if ( product['error'] ) return res.status(400).send(product);
    } // If all products exist, we continue with the update
    const carts = await CM.updateProductsFromCart(cartId, products);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

// PUT Quantity of Product From Cart
cartsRouter.put('/:cid/product/:pid', async (req, res) => {
    let { quantity } = req.body;
    let cartId = req.params.cid;
    let productId = req.params.pid;
    const carts = await CM.updateProductQuantityFromCart(cartId, productId, quantity);
    carts['error'] ? res.status(400).send(carts) : res.send({carts});
});

export default cartsRouter;