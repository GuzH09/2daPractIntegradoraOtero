import jwt from "jsonwebtoken";
import userModel from "./models/usersModel.js";
import { isValidPassword } from "../utils/functionsUtil.js";

export default class userManagerDB {
    async getAllUsers() {
        try {
            const users = await userModel.find().lean();
            const usersWithStrIds = users.map(user => {
                return {
                    ...user,
                    _id: user._id.toString()
                };
            });
            return usersWithStrIds;
        } catch (error) {
            return {error: error.message};
        }
    }

    async getUser(uid) {
        try {
            const user = await userModel.findOne({_id:uid}).lean()
            if (!user) return {error: "Error login user."};
            return user;
        } catch (error) {
            return {error: "User doesnt exists."};
        }
    }

    async registerUser(user) {
        const { first_name, last_name, email, age, password } = user;

        if (!first_name || !last_name || !email || !age || !password ) {
            return {error: "Error registering user."};
        }

        try {
            const result = await userModel.create({ first_name, last_name, email, age, password });
            return {success: "User added."};
        } catch (error) {
            return {error: error.message};
        }
    }

    async loginUser(email, password) {
        if (!email || !password ) {
            return {error: "Error login user."};
        }

        try {
            const user = await userModel.findOne({ email }).lean();
            if (!user) return {error: "Error login user."};
            if (isValidPassword(user, password)) {
                delete user.password;
                return jwt.sign(user, "coderSecret", {expiresIn: "1h"});
            }
            return {error: "Error login user."};
        } catch (error) {
            return {error: error.message};
        }
    }
}