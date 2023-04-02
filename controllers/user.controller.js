import userModel from "../models/user.model.js";

export const getUserById = async (req, res, next) => {
    try {
        const userId = req.params.id;
        const user = await userModel.findById(userId);

        if(!user) {
            const err = new Error("User tidak ditemukan.");
            err.statusCode = 404;
            throw err;
        }

        res.status(200).json(user)
    } catch (err) {
        next(err)
    }
}

export const getAllUser = async (req, res, next) => {
    try {
        const users = await userModel.find();

        res.status(200).json(users);
    } catch (err) {
        next(err);
    }
}