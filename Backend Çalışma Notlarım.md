# Backend Çalışma Notlarım

**Sık Kullanılan HTTP Yanıt Kodları**

- 200: OK (İstek başarılı)
- 401: Unauthorized (Yetki Hatası)
- 403: Forbidden (Hatalı Erişim İsteği)
- 404: Not Found (Kaynak bulunamadı)
- 500: Internal Server Error (Sunucu içerisinde hata oluştu)

# Idempotent

Http metotlarından GET, PUT, DELETE **idempotent** yapıda iken POST idempotent değildir.

Peki nedir bu **idempotent**? Birden fazla defa çağırılmasında sakınca olmayan, nihai sonucu değiştirmeyecek çağrımlara idempotent yapıda diyebiliriz. Örneğin bir Http Get metodunu üst üste istediğiniz kadar çağırabilirsiniz. Bu sonucu değiştiremeyecektir. Yada Http Delete metodunu bir kere çağırdığınızda veriyi sildiğinizi düşünelim. 2. yada 3. çağrımlarda veride bir değişiklik olmaz. Zaten silinmiştir.

# **Rounting**

Startup.cs içersinde çeşitli konfigürasyonlar yapabiliriz. Varsayılan olarak aşağıdaki yapılandırma ayarı geliyor. 

https://www.abc.com/home/list

Buradaki ilk kısım protokol, ikinci kısım domain name, üçüncü kısım controller, dördüncü kısım ise action kısmına karşılık geliyor.

```csharp
app.MapControllerRoute(
    name: "default",
    pattern: "{controller}/{action}/{id?}"); // id olmak zorunda değil
    pattern : "{controller = Home}/{action = Index}/{id?}" // default olarak değer atayabiliriz
```

# Views

MVC yapısındaki **view**, uygulamanın kullanıcı arayüzünü oluşturan katmandır. Bu katman, **controller** tarafından sağlanan verileri alır ve kullanıcıya görsel olarak sunar. **View**, verilerin nasıl göründüğüne odaklanırken, kullanıcı etkileşimlerini de işleyerek uygulamanın görünümünü kontrol eder.

**Razor**, ASP.NET uygulamalarında kullanılan bir **view engine**'dir ve **HTML** ile **C# kodunun** birlikte yazılmasına olanak tanır. Razor, **dinamik web sayfaları** oluştururken, sunucu tarafındaki C# kodlarını **@** sembolü ile gömülü şekilde yazmanıza imkan verir.

Viewlar içerisinde kullanacağımız modelleri gerekli View kısımlarında tanıtmamız gerekiyor. Yoksa modeller üzerindeki bilgilere ulaşamayız. Örneğin aşağıda ilk satırda @model Course ile bir model tanıtıldı. Ardından gerekli olduğu noktalarda @Model.Id, @Model,Title sözdizimleriyle gerekli id, title bilgileri modelden alınmıştır.

![image.png](image.png)

# Models

MVC yapısındaki **model**, uygulamanın veri yapısını ve iş mantığını temsil eden katmandır. Bu katman, veri tabanı ile etkileşime girer ve verilerin işlenmesini sağlar. **Model**, uygulamanın mantıklı ve tutarlı olmasını sağlayarak, verilerin doğruluğunu ve bütünlüğünü kontrol eder.

Basit bir model tanım örneği:

```csharp
// Represents a course with an ID, title, image, and description
public class Course
{
			public int Id { get; set; }
	   
		  public string? Title { get; set; }
	
	    public string? Image { get; set; }
	
	    public string? Description { get; set; }
	
}
```

# Static Files

[ASP.NET](http://ASP.NET) Core projelerinde statik dosyaları da projeye dahil edebiliriz. (Resim, video vs.) 

Bu dosyaları wwwroot klasörü altında yeni bir dosya oluşturup gruplayabiliriz.

![image.png](image%201.png)

# Bootstrap

Eklenecek

# Layout

**Layout**, bir web sayfasından sık kullanılan merkezi/ortak öğeleri (örneğin navigation menü ve footer bar gibi) tek bir yapıda tanımlamayı ve her yeni sayfa ihtiyacı ortaya çıktığında ortak yapıların tekrar tekrar kodlanmasını önlemek için kullanılan bir yapıdır.

Layout dosyamızı düzenliyoruz.

![image.png](image%202.png)

Ortak olmayan noktalar için body bloğu içerisinde @RenderBody() ile bilgiler çağrılır.

_ViewStart.cshtml dosyasında hangi layout default olarak kullanılmalı belirtilmeli.

```csharp
@{
Layout = "~/Views/Shared/_Layout.cshtml";
}
```

# Partial Views

**Partial View**, belirli bir view'in sadece bir kısmını temsil eder ve ana **view** içerisinde gömülü olarak kullanılır. Bu, **yeniden kullanılabilirliği** artırır ve sayfa üzerinde ortak kullanılan bileşenleri (örneğin, header, footer, navigation) tekrar yazmaya gerek kalmadan kolayca yerleştirmenizi sağlar. 

Shared klasörü altında yeni bir dosya oluşturuyoruz. ( _NavBar.cshtml )

![image.png](image%203.png)

 İçerisinde her sayfa düzeninde tekrar eden navigasyon barının bilgileri olacak şekilde düzenliyoruz.

![image.png](image%204.png)

Ve kullanılacak noktalardan bu layout bilgisini alıyoruz.

```csharp
@await Html.PartialAsync(”_Navbar”)
```

![image.png](image%205.png)

# Repository Sınıfı

Halihazırda daha çalışmalarımın başlarında olduğum için temel konuları kapsayan projemde verileri tutması için bir yapıya ihtiyaç duyuyorum. Daha veri tabanı vs. gibi konuları detaylı ele almadığım için şimdilik repository sınıfı oluşturacağım.

![image.png](image%206.png)

Gerekli durumlarda [Repository.Courses](http://Repository.Courses) altından bilgileri alacağım.

# Tag Helpers

**Tag Helpers**, **ASP.NET Core MVC ve Razor Pages** içinde **HTML etiketlerini sunucu tarafında dinamik olarak oluşturmak ve yönetmek için kullanılan bir özellik**dir. **Razor syntax'ına** alternatif olarak geliştirilmiştir ve özellikle **HTML benzeri bir deneyim sunarak kod okunabilirliğini artırır.**

### **Tag Helpers ile Razor Syntax Karşılaştırması**

| **Özellik** | **Razor Syntax (@Html)** | **Tag Helper** |
| --- | --- | --- |
| **Form Elemanı** | `@Html.TextBoxFor(m => m.Email)` | `<input asp-for="Email" />` |
| **Link** | `@Html.ActionLink("Hakkımızda", "About", "Home")` | `<a asp-controller="Home" asp-action="About">Hakkımızda</a>` |
| **Checkbox** | `@Html.CheckBoxFor(m => m.IsChecked)` | `<input asp-for="IsChecked" type="checkbox" />` |

# LibMan

**LibMan (Library Manager)**, **Visual Studio** içinde kullanılan bir istemci tarafı kitaplık yöneticisidir. **JavaScript, CSS ve diğer istemci tarafı bağımlılıklarını** yönetmek için kullanılır. **Özellikle ASP.NET Core ve MVC projelerinde** popülerdir.

**LibMan ve NuGet** arasındaki farkları anlamak için temel kullanım alanlarına bakmak gerekir:

| **Özellik** | **LibMan** | **NuGet** |
| --- | --- | --- |
| **Amaç** | İstemci tarafı kütüphaneleri (JS, CSS) yönetmek için | .NET ve C# için bağımlılık yönetimi |
| **Kullanım Alanı** | Web projelerinde (ASP.NET, MVC, Blazor) | .NET projelerinde (Web API, Console, MVC, Blazor, vs.) |
| **Bağımlılık Yönetimi** | CDN'lerden veya yerel depolardan JS/CSS alır | .NET paketlerini NuGet Gallery’den çeker |
| **Depolama Konumu** | `wwwroot/lib/` veya belirlenen klasöre yükler | `packages` klasörüne veya `obj` içindeki cache'e yükler |
| **Paket Formatı** | JSON tabanlı (`libman.json`) | `.nupkg` dosyaları |
| **Komut Satırı Kullanımı** | `libman restore` | `dotnet add package <paketAdı>` veya `nuget install` |
| **Alternatifleri** | npm, yarn | Paket yöneticisi olarak başka alternatifi yok |

### **Özet:**

- **LibMan**, **JavaScript ve CSS gibi istemci tarafı bağımlılıklarını** yönetir.
- **NuGet**, **C#/.NET kütüphanelerini ve bağımlılıklarını** yönetir.

Yani, **NuGet bir .NET paket yöneticisidir**, **LibMan ise frontend bağımlılıklarını yönetir.**

🚀 **ASP.NET projelerinde genellikle ikisi bir arada kullanılır.**

# ViewBag - ViewData

Model üzerinde olmayan bir veriyi bu yapılarla oluşturup sayfa üzerinde kullanabiliriz.

Örneğin her sayfanın title bilgisini model üzerinden güncellemek yerine ViewBag kullanarak tanımlayabiliriz.

Layout dosyamız üzerindeki title kısmını ayarlıyoruz.

```csharp
 <title>@ViewBag.Title - MeetingApp</title>
```

Ardından kullanılacak View dosyalarına tanıtıyoruz.

```csharp
@{
ViewBag.Title = "Meeting Attendance";
}
```

Artık sayfayı yenilediğimiz zaman dinamik olarak title kısmı değişiyor.

```csharp
int clock = DateTime.Now.Hour;
[ViewBag.Greeting](https://viewbag.greeting/) = clock < 12 ? "Good Morning" : "Good Afternoon";
ViewData["Greeting"] = clock < 12 ? "Good Morning" : "Good Afternoon";

//Yukarıda anlık saate göre kullanıcıya selam veren bir viewbag, viewdata tanımı vardır.
//İlgili konumdan @ViewBag.Greeting veya @ViewData["Greeting"] yazarak bu veriyi çağırabiliriz
```

# Model Validation

ASP.NET’te **model validation (model doğrulama)**, kullanıcıdan gelen verilerin doğruluğunu ve bütünlüğünü kontrol etmek için kullanılır. Model doğrulama sayesinde, yanlış veya eksik veri kaydedilmeden önce tespit edilebilir ve kullanıcıya uygun hata mesajları gösterilebilir.

Model doğrulama şu amaçlarla kullanılır:

- Kullanıcının zorunlu alanları doldurduğunu kontrol etmek
- Girilen verinin belirli bir formatta olup olmadığını denetlemek
- Maksimum ve minimum değer sınırlarını belirlemek
- E-posta gibi özel formatların doğruluğunu kontrol etmek

**Validation Attributes (Doğrulama Öznitelikleri):**

- [[ValidateNever]](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.modelbinding.validation.validateneverattribute): Bir özelliğin veya parametrenin doğrulamanın dışında tutulması gerektiğini gösterir.
- [[CreditCard]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.creditcardattribute): Özelliğin kredi kartı biçiminde olduğunu doğrular. jQuery Doğrulama Ek Yöntemleri gerektirir. (Konuya ayrı olarak bakılmalı !!!)
- [[Compare]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.compareattribute): Modeldeki iki özelliğin eşleştiklerini doğrular.
- [[EmailAddress]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.emailaddressattribute): Özelliğin e-posta biçimi olduğunu doğrular.
- [[Phone]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.phoneattribute): Özelliğin telefon numarası biçimine sahip olduğunu doğrular.
- [[Range]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.rangeattribute): Özellik değerinin belirtilen aralık içinde olduğunu doğrular.
- [[RegularExpression]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.regularexpressionattribute): Özellik değerinin belirtilen normal ifadeyle eşleştiklerini doğrular.
- [[Required]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.requiredattribute): Alanın null olmadığını doğrular. Bu özniteliğin davranışıyla ilgili ayrıntılar için bkz [`[Required]` . öznitelik](https://learn.microsoft.com/tr-tr/aspnet/core/mvc/models/validation?view=aspnetcore-9.0#non-nullable-reference-types-and-required-attribute) .
- [[StringLength]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.stringlengthattribute): Dize özellik değerinin belirtilen uzunluk sınırını aşmadığını doğrular.
- [[Url]](https://learn.microsoft.com/en-us/dotnet/api/system.componentmodel.dataannotations.urlattribute): Özelliğin BIR URL biçimi olduğunu doğrular.
- [[Remote]](https://learn.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.mvc.remoteattribute): Sunucuda bir eylem yöntemi çağırarak istemcideki girişi doğrular. Bu özniteliğin davranışıyla ilgili ayrıntılar için bkz [`[Remote]` . öznitelik](https://learn.microsoft.com/tr-tr/aspnet/core/mvc/models/validation?view=aspnetcore-9.0#remote-attribute) .

## **Controller'da Model Doğrulama Kullanımı**

Controller’da `ModelState.IsValid` ile doğrulama yapılır. Eğer model doğrulama başarısız olursa, hata mesajları kullanıcıya döndürülebilir.

```csharp
[HttpPost]
public async Task<IActionResult> Create(Movie movie)
{
    if (!ModelState.IsValid)
    {
        return View(movie);
    }

    _context.Movies.Add(movie);
    await _context.SaveChangesAsync();

    return RedirectToAction(nameof(Index));
}
```

Eğer doğrulama hatası varsa, `ModelState` hata mesajlarını içerecektir. 

Web API denetleyicilerinin [ApiController] [özniteliğine](https://learn.microsoft.com/tr-tr/dotnet/api/microsoft.aspnetcore.mvc.apicontrollerattribute) sahip olup olmadığını denetlemeleri `ModelState.IsValid` gerekmez. Bu durumda, model durumu geçersiz olduğunda hata ayrıntılarını içeren otomatik bir HTTP 400 yanıtı döndürülür.

**ASP.NET’te model validation, Data Annotations veya Fluent Validation gibi tekniklerle yapılabilir.** 

## Data Annotations ile Validation

Data Annotations yukarıda bahsedilen Validation Attributes yardımıyla yapılır.

```csharp
using System.ComponentModel.DataAnnotations;

public class User
{
    [Required(ErrorMessage = "İsim alanı zorunludur.")]
    [StringLength(50, ErrorMessage = "İsim en fazla 50 karakter olabilir.")]
    public string Name { get; set; }

    [Required(ErrorMessage = "E-posta alanı zorunludur.")]
    [EmailAddress(ErrorMessage = "Geçerli bir e-posta adresi giriniz.")]
    public string Email { get; set; }

    [Range(18, 99, ErrorMessage = "Yaş 18 ile 99 arasında olmalıdır.")]
    public int Age { get; set; }
}
```

## **Fluent Validation ile Model Doğrulama**

Alternatif olarak **FluentValidation** kullanabilirsiniz. Daha esnek bir doğrulama mantığı sağlar.

### **FluentValidation Kurulum**

NuGet üzerinden **FluentValidation.AspNetCore** paketi yüklenmelidir.

```bash
dotnet add package FluentValidation.AspNetCore
```

### **Fluent Validation Kullanımı**

Öncelikle bir **Validator** sınıfı oluşturun:

```csharp
using FluentValidation;

public class UserValidator : AbstractValidator<User>
{
    public UserValidator()
    {
        RuleFor(x => x.Name).NotEmpty().WithMessage("İsim boş olamaz.")
                            .MaximumLength(50).WithMessage("İsim en fazla 50 karakter olabilir.");

        RuleFor(x => x.Email).NotEmpty().WithMessage("E-posta boş olamaz.")
                             .EmailAddress().WithMessage("Geçerli bir e-posta adresi giriniz.");

        RuleFor(x => x.Age).InclusiveBetween(18, 99).WithMessage("Yaş 18 ile 99 arasında olmalıdır.");
    }
}
```

Daha sonra bu doğrulayıcıyı DI container’a kaydedin:

```csharp
builder.Services.AddControllers().AddFluentValidation(fv =>
{
    fv.RegisterValidatorsFromAssemblyContaining<UserValidator>();
});
```

Son olarak, Controller’ınızda doğrulama hatalarını yakalayabilirsiniz:

```csharp
[HttpPost]
public IActionResult Register(User user)
{
    var validator = new UserValidator();
    var result = validator.Validate(user);

    if (!result.IsValid)
    {
        return BadRequest(result.Errors);
    }

    return Ok("Kayıt başarıyla tamamlandı.");
}
```

# ORM Nedir?

ORM (Object-Relational Mapping), nesne yönelimli programlama (OOP) dillerinde kullanılan bir tekniktir ve veri tabanı yönetimini kolaylaştırmak için geliştirilmiştir. ORM sayesinde, veri tabanı işlemleri SQL sorguları yazmadan nesneler ve metotlar kullanılarak gerçekleştirilebilir.

### **ORM’in Temel Faydaları:**

1. SQL Yazma Zorunluluğunu Azaltır → SQL sorguları yerine OOP diline uygun kodlarla veri tabanı işlemleri yapılır.
2. Veri tabanı Bağımsızlığı Sağlar → Farklı veri tabanı yönetim sistemleri arasında geçişi kolaylaştırır.
3. Güvenliği Artırır → SQL Injection gibi saldırılara karşı daha güvenlidir.
4. Kod Tekrarını Azaltır ve Bakımı Kolaylaştırır → Model sınıfları kullanarak düzenli ve tekrar kullanılabilir kod yazmayı sağlar.

Popüler ORM’ler:

- C# / .NET → Entity Framework Core (EF Core), Dapper
- Python → SQLAlchemy, Django ORM
- Java → Hibernate
- JavaScript (Node.js) → Sequelize, TypeORM

# Entity Framework Core

**Entity Framework Core (EF Core)**, **.NET uygulamalarında** veri tabanı işlemlerini yönetmek için kullanılan **modern, hafif ve platform bağımsız bir ORM (Object-Relational Mapper)** kütüphanesidir.

EF Core, **C# ve .NET ile SQL yazmadan** veri tabanı işlemleri yapmanı sağlar. **LINQ** kullanarak veri tabanı sorguları yazabilir, **Code-First** veya **Database-First** yaklaşımlarıyla çalışabilirsin.

### **EF Core’un Temel Özellikleri:**

- Platform Bağımsızdır → .NET 6, .NET 7, .NET 8 ve üstüyle çalışır.
- Yüksek Performanslıdır → Klasik Entity Framework'e göre daha hızlıdır.
- Çeşitli Veri tabanlarını Destekler → MSSQL, PostgreSQL, MySQL, SQLite, In-Memory vb.
- Migration Desteği Sunar → Veri tabanı şemanı C# koduyla yönetebilirsin.
- LINQ ile Çalışır → SQL yazmadan nesne tabanlı sorgular yapabilirsin.
- Code-First & Database-First Yaklaşımı → Veri tabanını koddan veya var olan DB’den oluşturabilirsin.
- Repository ve Unit of Work ile Entegre Edilebilir → Temiz mimari ile çalışmaya uygundur.

### **EF Core Migrations Nedir?**

EF Core Migrations, veritabanını koddan yönetmeni sağlayan bir mekanizmadır.

- Code-First yaklaşımını kullanarak veritabanında değişiklik yapabilmeni sağlar.
- Tablolara yeni sütun ekleme, veri tipi değiştirme gibi işlemleri yönetir.
- SQL komutları yazmadan, C# koduyla veritabanı şemasını güncellemeni sağlar.

# **Code-First ve Database-First Yaklaşımları**

EF Core'da **veritabanını nasıl oluşturduğuna** göre iki farklı yaklaşım vardır.

## **✅ Code-First Yaklaşımı**

Code-First yaklaşımında **önce C# sınıflarını yazarsın**, sonra bu sınıflardan veritabanını oluşturursun.

📌 **Adımlar:**

1️⃣ Model sınıflarını oluştur

2️⃣ DbContext sınıfını oluştur

3️⃣ Migration işlemleri ile veritabanını oluştur ve yönet

```csharp
// Model sınıf tanımı
public class Kullanici
{
    public int Id { get; set; }
    public string Ad { get; set; }
    public string Email { get; set; }
}

```

## **DbContext ve Options**

### **1️⃣ DbContext Nedir?**

- DbContext, Entity Framework Core’un en temel bileşenlerinden biridir.
- Veritabanı ile uygulama arasındaki bağlantıyı yönetir.
- Tabloları, sorguları, veri ekleme/güncelleme/silme işlemlerini takip eder.
- Migration ve veri işlemlerini yönetir**.**

### **2️⃣ DbContext Nasıl Tanımlanır?**

DbContext sınıfını oluşturmak için `Microsoft.EntityFrameworkCore` kütüphanesini kullanmalısın.

📌 **Örnek:**

```csharp
using Microsoft.EntityFrameworkCore;

public class UygulamaDbContext : DbContext
{
    public UygulamaDbContext(DbContextOptions<UygulamaDbContext> options) : base(options)
    {
    }

    public DbSet<Kullanici> Kullanicilar { get; set; }
}

```

---

### **3️⃣ `DbContextOptions` ve `options` Parametresi Ne İşe Yarar?**

- DbContextOptions, DbContext'in nasıl çalışacağını belirleyen yapılandırma ayarlarını taşır.
- options parametresi, hangi veritabanını kullanacağını ve bağlantı ayarlarını içerir.

İşte detaylar:

- Hangi veritabanı sağlayıcısının kullanılacağını belirler (SQL Server, PostgreSQL, SQLite vb.).
- Bağlantı string’ini içerir (veritabanının adresini belirtir).
- Lazy Loading, Logging gibi gelişmiş ayarları yapılandırabilir.

**Örnek: DbContext’i Startup dosyasında ayarlamak**

`Program.cs` veya `Startup.cs` içinde `DbContextOptions` kullanarak bağlanma işlemi yapılır.

```csharp
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddDbContext<UygulamaDbContext>(options =>
    options.UseSqlServer("Server=.;Database=UygulamaDB;Trusted_Connection=True;"));

var app = builder.Build();
app.Run();
```

---

Tabii ki aşağıdaki gibi bir bağlantı türünü appsettings.json dosyasında tanımlayabiliriz. Ardından bunu direkt `Program.cs` veya `Startup.cs` içinde çağırabiliriz.

```bash
//SqLite için bir default tanım
"ConnectionStrings": {
"DefaultConnection": "Data Source = efcoreApp.db"
}
```

```csharp
//Tanımladığımız bağlantı türünü gerekli dosya içerisinde tanıtıyoruz

builder.Services.AddDbContext<DataDbContext>(options =>
options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection")));
```

### **4️⃣ Farklı Veritabanları İçin `DbContextOptions` Kullanımı**

Entity Framework Core farklı veritabanlarını destekler. İşte bazı örnekler:

✅ **SQL Server Kullanımı:**

```csharp
options.UseSqlServer("Server=.;Database=UygulamaDB;Trusted_Connection=True;");
```

✅ **PostgreSQL Kullanımı:**

```csharp
options.UseNpgsql("Host=localhost;Database=UygulamaDB;Username=postgres;Password=1234;");
```

✅ **SQLite Kullanımı (Hafif, Dosya Tabanlı Veritabanı):**

```csharp
options.UseSqlite("Data Source=uygulama.db;");
```

✅ **In-Memory Database (Test İçin):**

```csharp
options.UseInMemoryDatabase("TestDB");
```

Migration işlemi:

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```

📌 **Sonuç:**

Bu komutları çalıştırdığında, EF Core otomatik olarak `Kullanicilar` tablosunu oluşturur.

---

## ✅ Database-First Yaklaşımı

Mevcut bir veritabanın varsa, EF Core otomatik olarak tabloları model sınıflarına dönüştürebilir.

📌 Adımlar:

1️⃣ Mevcut bir veritabanın olmalı.

2️⃣ EF Core'u kullanarak C# model sınıflarını oluşturmalısın.

Komut:

```bash
dotnet ef dbcontext scaffold "Server=.;Database=OrnekDB;Trusted_Connection=True;" Microsoft.EntityFrameworkCore.SqlServer -o Models
```

Bu komut, mevcut `OrnekDB` veritabanındaki tabloları C# sınıflarına çevirir.