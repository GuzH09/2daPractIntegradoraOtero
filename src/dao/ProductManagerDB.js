import productModel from './models/productModel.js';

export default class ProductManagerDB {
    async getProducts() {
        try {
            const products = await productModel.find().lean();
            const productsWithStrIds = products.map(product => {
                return {
                    ...product,
                    _id: product._id.toString()
                };
            });
            return productsWithStrIds;
        } catch (error) {
            return {error: error.message};
        }
    }

    async getProductById(id) {
        try {
            const product = await productModel.findOne({_id: id}).lean();
            return product
        } catch (error) {
            return {error: error.message}
        }
    }

    async addProduct(productObj) {
        try {
            const validatedData = this.#validateNewProduct(productObj)

            let fileProducts = await this.getProducts();
        
            if (fileProducts.some(product => product.code === validatedData.code)) {
                return {error: `Error: code ${validatedData.code} already exists.`};
            }

            const {title, description, code, price, stock, category, thumbnails} = validatedData;

            const result = await productModel.create({title, description, code, price, stock, category, thumbnails: thumbnails ?? []});
            return {success: "Product added."};
        } catch (error) {
            return {error: error.message};
        }
    }

    async updateProduct(id, productData) {
        try {
            const validatedData = this.#validateUpdateProduct(productData)

            const result = await productModel.updateOne({_id: id}, productData);
            
            return {success: "Product updated."};
        } catch(error) {
            return {error: error.message};
        }
    }

    async deleteProduct(id) {
        try {
            const result = await productModel.deleteOne({_id: id});
            if (result.deletedCount === 0) return {error: `Product with id ${id} not found.`};
            return {success: "Product deleted."};
        } catch(error) {
            return {error: error.message};
        }
    }
    
    #validateNewProduct(objectFields) {
        const newObjectData = {}

        const requiredFields = ['title', 'description', 'code', 'price', 'stock', 'category']

        // Validates fields
        for (const field in objectFields) {
            // If field is missing and field is required : Missing Field
            if ( !objectFields[field] && requiredFields.includes(field) ) {
                throw new Error(`Missing field: ${field} .`);
            }
            // If field is not missing add to new object
            if ( objectFields[field] ) {
                newObjectData[field] = objectFields[field];
            }

            switch ( field ) {
                case "title":
                case "description":
                case "code":
                case "category":
                    if ( typeof objectFields[field] !== 'string' ) {
                        throw new Error(`Invalid type for field: ${field}. Expected: String.`);
                    }
                    break;
                case "price":
                case "stock":
                    // if ( typeof objectFields[field] !== 'number' ) {
                    //     return { error: `Invalid type for field: ${field}. Expected: Number.` };
                    // }
                    break;
                case "thumbnails":
                    // It only returns an error if the thumbnail HAS a value, but it is not an array.
                    if ( objectFields[field] && !Array.isArray(objectFields[field]) ) {
                        throw new Error(`Invalid type for field: ${field}. Expected: array of strings.`);
                    }
                    break;
                default:
                    break;
            }
        }

        return newObjectData;
    }

    // Validation Function for Updating Product
    #validateUpdateProduct = (objectFields) => {
        const newObjectData = {}

        // Validates new Fields
        for (const field in objectFields) {
            // If field is not undefined, push the field into the new object
            if ( objectFields[field] ) {
                newObjectData[field] = objectFields[field];
            }

            switch ( field ) {
                case "title":
                case "description":
                case "code":
                case "category":
                    // It only returns an error if the title-description-code-category HAS a value, but it is not a string.
                    if ( objectFields[field] && typeof objectFields[field] !== 'string' ) {
                        throw new Error(`Invalid type for field: ${field}. Expected: String.`);
                    }
                    break;
                case "price":
                case "stock":
                    // It only returns an error if the stock or price HAS a value, but it is not a number.
                    if ( objectFields[field] && typeof objectFields[field] !== 'number' ) {
                        throw new Error(`Invalid type for field: ${field}. Expected: Number.`);
                    }
                    break;
                case "thumbnails":
                    // It only returns an error if the thumbnail HAS a value, but it is not an array.
                    if ( objectFields[field] && !Array.isArray(objectFields[field]) ) {
                        throw new Error(`Invalid type for field: ${field}. Expected: array of strings.`);
                    }
                    break;
                default:
                    break;        
            }
        }

    return newObjectData;
    }
}