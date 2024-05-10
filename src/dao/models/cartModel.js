import mongoose from "mongoose";

const cartCollection = "carts";

// Esta vez, para el modelo de Carts, en su propiedad products, el id de cada producto 
// generado dentro del array tiene que hacer referencia al modelo de Products. ✅

// Modificar la ruta /:cid para que al traer todos los productos, los traiga completos 
// mediante un “populate”. De esta manera almacenamos sólo el Id, pero al solicitarlo 
// podemos desglosar los productos asociados.

const cartSchema = new mongoose.Schema({
    products: {
        type: [
            {
                product: {
                    type: mongoose.Schema.ObjectId,
                    ref: "products"
                },
                quantity: {
                    type: Number,
                    default: 1
                }
            }
        ],
        require: false,
        default: []
    }
});

cartSchema.pre('find', function() {
    this.populate('products.product')
})

const cartModel = mongoose.model(cartCollection, cartSchema);

export default cartModel;