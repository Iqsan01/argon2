//Error handller middleware
const errorHandler = (err, req, res, next) => {
    console.error(err);
    const statusCode = err.statusCode || 500;
    const errorMessage = err.message || "Internal Error";
    res.status(statusCode).json({ error: errorMessage });
}

const notFound = (req, res) => {
    res.status(404).json({error: "Not Found"})
}


export default {
    errorHandler,
    notFound
}