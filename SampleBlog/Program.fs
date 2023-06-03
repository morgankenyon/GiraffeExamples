module SampleBlog.App

open System
open System.IO
open Microsoft.AspNetCore.Builder
open Microsoft.AspNetCore.Cors.Infrastructure
open Microsoft.AspNetCore.Hosting
open Microsoft.Extensions.Hosting
open Microsoft.Extensions.Logging
open Microsoft.Extensions.DependencyInjection
open Giraffe
open Microsoft.AspNetCore.Http
open Microsoft.AspNetCore.Authentication.JwtBearer
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Tokens
open System.Text
open System.Security.Claims
open Microsoft.AspNetCore.Authentication
open Microsoft.AspNetCore.Authentication.Cookies
open System.Runtime.CompilerServices

// ---------------------------------
// Models
// ---------------------------------
[<CLIMutable>]
type LoginRequest = { username: string; password: string }

type Message =
    {
        Text : string
    }

type Post =
    { 
        Body : string
        Author : string
        Date : DateTime
    }


// ---------------------------------
// Middleware
// ---------------------------------
type SampleBlogMiddleware (next : RequestDelegate,
                           handler : HttpHandler,  //TODO figure out why when I remove this, authentication breaks
                           loggerFactory : ILoggerFactory) =
    let logger = loggerFactory.CreateLogger<SampleBlogMiddleware>()

    member __.Invoke(ctx : HttpContext) =
        task {
            let cookie = ctx.Request.Cookies["SampleBlogToken"]
            logger.LogInformation($"Cookie {cookie}")
            match ctx.GetCookieValue "SampleBlogToken" with
            | None ->
                logger.LogInformation("Could not find cookie")
            | Some token -> 
                logger.LogInformation("Could find cookie")
                ctx.Request.Headers.Add("Authorization", $"Bearer {token}");

            logger.LogInformation("Adding bearer token to authentication pipeline")
            return! next.Invoke ctx
        }

[<Extension>]
type ApplicationBuilderMiddleware() =
    [<Extension>]
    static member UseCookieJwt
        (builder: IApplicationBuilder, handler : HttpHandler) =
        builder.UseMiddleware<SampleBlogMiddleware> handler |> ignore
        builder


// ---------------------------------
// Views
// ---------------------------------

module Views =
    open Giraffe.ViewEngine

    let layout (content: XmlNode list) =
        html [] [
            head [] [
                title []  [ encodedText "Flog - F# Blog" ]
                
                link [ _rel  "stylesheet"
                       _type "text/css"
                       _href "/bulma.css" ]
                link [ _rel  "stylesheet"
                       _type "text/css"
                       _href "/main.css" ]
            ]
            body [] [
                div [ _class "container" ] content
            ]
            
        ]

    let partial () =
        h1 [] [ encodedText "SampleBlog" ]

    let indexOld (model : Message) =
        [
            partial()
            p [] [ encodedText model.Text ]
        ] |> layout


    let index =
        let pageTitle = "Index"

        
        [ h1 [] [ str pageTitle ]
          div [] [
            p [] [ str "This is the home page" ]

          ] ]
        |> layout
    
    let login = 
        [ div [] [
            h1 [] [ str "Login" ]
            p [] [ str "Any random password will be accepted" ]
            form [ _action "/login"; _method "post" ] [
                div [ _class "field" ] [
                    label [ _class "label"; _for "username" ] [ str "Username" ]
                    input [ _id "username"
                            _type "text"
                            _name "username" ]
                ]
                div [ _class "field" ] [
                    label [ _class "label"; _for "password" ] [
                        str "Password"
                    ]
                    input [ _id "password"
                            _type "password"
                            _name "password" ]
                ]
                div [] [ input [ _type "submit" ] ]
            ]

        ] ] |> layout

    let loginSubmitView request =
        let pageTitle = "Thank you!"

        [ h1 [] [ str pageTitle ]
          p [] [
              str "Thank you for submitting login stuff"
          ] ]
        |> layout

// ---------
// Token Stuff
// ---------

let secret = "testkey_this_needs_to_be_big_or_else_an_error_occurs"

let generateToken email =
    let tokenHandler = new JwtSecurityTokenHandler()
    let key = Encoding.ASCII.GetBytes(secret)
    let mutable tokenDescriptor = new SecurityTokenDescriptor()
    let claim = new Claim(ClaimTypes.Name, email)
    let claims = [| claim |]
    tokenDescriptor.Subject <- new ClaimsIdentity(claims)
    tokenDescriptor.Expires <- System.Nullable(DateTime.UtcNow.AddMinutes(10.0))
    tokenDescriptor.SigningCredentials <- new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    let token = tokenHandler.CreateToken(tokenDescriptor)
    tokenHandler.WriteToken(token)

let authorize = requiresAuthentication (challenge JwtBearerDefaults.AuthenticationScheme)

// ---------------------------------
// Web app
// ---------------------------------

let indexHandler =
    htmlView Views.index

let loginHandler: HttpHandler =
    // Do stuff
    htmlView Views.login



let loginSubmitHandler: HttpHandler =
    fun (next: HttpFunc) (ctx: HttpContext) ->
        task {
            // Binds a form payload to a Car object
            let! request = ctx.BindFormAsync<LoginRequest>()

            let token = generateToken request.username

            let cookieOptions = new CookieOptions(); 
            cookieOptions.Expires <- DateTimeOffset.Now.AddDays(1);
            cookieOptions.Path <- "/"
            
            ctx.Response.Cookies.Append("SampleBlogToken", token, cookieOptions);

            //return! indexHandler next ctx
            return! (redirectTo false "/") next ctx
            // Sends the object back to the client
            //return! ctx.WriteHtmlViewAsync(Views.loginSubmitView request)
        }

let loginRoutes: HttpHandler =
    choose [ GET >=> choose [ route "/login" >=> loginHandler ]
             POST
             >=> choose [ route "/login" >=> loginSubmitHandler ] ]

// let webApp =
//     choose [
//         GET >=>
//             choose [
//                 route "/" >=> indexHandler "world"
//                 routef "/hello/%s" indexHandler
//             ]
//         setStatusCode 404 >=> text "Not Found" ]

let webApp =
    choose [ route "/login" >=> loginRoutes
             authorize
             >=> choose [ 
                    route "/" >=> indexHandler 
                    //routef "/hello/%s" indexHandler
                    routeCi "/testauth" >=> text "you're authorized" ] ]
// ---------------------------------
// Error handler
// ---------------------------------

let errorHandler (ex : Exception) (logger : ILogger) =
    logger.LogError(ex, "An unhandled exception has occurred while executing the request.")
    clearResponse >=> setStatusCode 500 >=> text ex.Message

// ---------------------------------
// Config and Main
// ---------------------------------

let configureCors (builder : CorsPolicyBuilder) =
    builder
        .WithOrigins(
            "http://localhost:5000",
            "https://localhost:5001")
       .AllowAnyMethod()
       .AllowAnyHeader()
       |> ignore

let configureApp (app : IApplicationBuilder) =
    let env = app.ApplicationServices.GetService<IWebHostEnvironment>()
    (match env.IsDevelopment() with
    | true  ->
        app.UseDeveloperExceptionPage()
    | false ->
        app .UseGiraffeErrorHandler(errorHandler)
            .UseHttpsRedirection())
        .UseCors(configureCors)
        .UseCookieJwt(webApp)
        .UseAuthentication()
        .UseStaticFiles()
        .UseGiraffe(webApp)

let authenticationOptions (o : AuthenticationOptions) =
    o.DefaultAuthenticateScheme <- JwtBearerDefaults.AuthenticationScheme
    o.DefaultChallengeScheme <- JwtBearerDefaults.AuthenticationScheme

let jwtBearerOptions (cfg : JwtBearerOptions) =
    let key = Encoding.ASCII.GetBytes(secret);
    cfg.SaveToken <- true
    cfg.RequireHttpsMetadata <- false
    cfg.TokenValidationParameters <- TokenValidationParameters (
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false,
        ClockSkew = TimeSpan.Zero
    )

let configureServices (services : IServiceCollection) =
    services.AddCors()
        .AddGiraffe()
        .AddAuthentication(authenticationOptions)
        .AddJwtBearer(Action<JwtBearerOptions> jwtBearerOptions) |> ignore

let configureLogging (builder : ILoggingBuilder) =
    builder.AddConsole()
           .AddDebug() |> ignore

[<EntryPoint>]
let main args =
    let contentRoot = Directory.GetCurrentDirectory()
    let webRoot     = Path.Combine(contentRoot, "WebRoot")
    Host.CreateDefaultBuilder(args)
        .ConfigureWebHostDefaults(
            fun webHostBuilder ->
                webHostBuilder
                    .UseContentRoot(contentRoot)
                    .UseWebRoot(webRoot)
                    .Configure(Action<IApplicationBuilder> configureApp)
                    .ConfigureServices(configureServices)
                    .ConfigureLogging(configureLogging)
                    |> ignore)
        .Build()
        .Run()
    0