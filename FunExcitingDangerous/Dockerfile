FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
USER $APP_UID
WORKDIR /app
EXPOSE 8080
EXPOSE 8081

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["FunExcitingDangerous/FunExcitingDangerous.csproj", "FunExcitingDangerous/"]
RUN dotnet restore "FunExcitingDangerous/FunExcitingDangerous.csproj"
COPY . .
WORKDIR "/src/FunExcitingDangerous"
RUN dotnet build "FunExcitingDangerous.csproj" -c $BUILD_CONFIGURATION -o /app/build

FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "FunExcitingDangerous.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=true

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "FunExcitingDangerous.dll"]
